"""Snapshot persistence.

The state file is the tool's memory: without it every run looks like a first
run and no drift is ever detected. It is written atomically (temp file in the
same directory, then ``os.replace``) so an interrupted run cannot leave a
truncated file that silently wipes the baseline.

The file is created ``0600``. It contains an inventory of your domains, mail
routing and certificate details — not secrets, but not something to leave
world-readable on a shared host either.

Every open goes through a file descriptor with ``O_NOFOLLOW`` and
``O_NONBLOCK``, and the descriptor is checked with ``fstat`` before a byte is
read. The state path is usually relative, so in CI it lands inside the
checked-out repository next to whatever else that job writes; a symlink planted
there would otherwise make this read — and then, through :meth:`save`, chmod —
some other file entirely. A corrupt baseline degrades to "no baseline", because
losing drift detection for one run beats a monitoring job that stops running. A
symlink or a FIFO is not a corruption, it is somebody's idea, and it raises.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from .models import Snapshot

log = logging.getLogger(__name__)

STATE_VERSION = 1
DEFAULT_STATE_PATH = Path(".dnsdrift/state.json")

# A snapshot history that grows without bound eventually makes every run slower
# and the file harder to inspect. Only the most recent snapshot per domain is
# needed for diffing.
_MAX_STATE_BYTES = 50 * 1024 * 1024
_READ_CHUNK = 1024 * 1024


class StateError(Exception):
    """The state file could not be read or written."""


class SnapshotStore:
    """Reads and writes the previous-scan baseline."""

    def __init__(self, path: str | Path = DEFAULT_STATE_PATH) -> None:
        self.path = Path(path).expanduser()
        self._snapshots: dict[str, Snapshot] = {}
        self._loaded = False

    def _read_bytes(self) -> bytes | None:
        """Read the state file through a descriptor, or return None if absent.

        ``O_NOFOLLOW`` so a symlink planted in the state directory cannot make
        this read — and later, through :meth:`save`, replace — some other file.
        Checked through a descriptor rather than by path: ``exists()`` followed
        by ``read_text()`` is two lookups of the same name, and whoever can write
        to that directory owns what happens in between.

        ``O_NONBLOCK`` is here for the same reason and against the same person.
        Opening a FIFO for reading blocks *inside* ``os.open`` until a writer
        appears, so the regular-file check below never gets the chance to reject
        one: a named pipe left at the state path hangs every run indefinitely
        rather than failing, and for a scheduled scan that means the reports
        simply stop arriving with nothing in the log. Cleared once the descriptor
        is known to be a regular file, where a short read would be a liability
        rather than a guard.

        The size is taken from ``fstat`` and checked again while reading: the
        first tells the truth about a regular file, the second catches one that
        grows underneath us.
        """
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        except OSError as exc:
            # ELOOP lands here: the path is a symlink and we refused to follow it.
            raise StateError(f"cannot open state file {self.path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise StateError(f"state file {self.path} is not a regular file; refusing to open it")
            if info.st_size > _MAX_STATE_BYTES:
                raise StateError(f"state file is implausibly large ({info.st_size} bytes)")
            os.set_blocking(fd, True)
            if stat.S_IMODE(info.st_mode) & 0o077:
                # Repaired through the descriptor, not the path. This file is an
                # inventory of your domains, mail routing and certificates.
                log.warning("state file %s was readable by others; tightening to 0600", self.path)
                os.fchmod(fd, 0o600)

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_STATE_BYTES:
                    raise StateError(f"state file {self.path} exceeds {_MAX_STATE_BYTES} bytes")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def load(self) -> dict[str, Snapshot]:
        """Load the baseline, returning an empty mapping if none exists.

        A corrupt state file is treated as "no baseline" rather than a fatal
        error: losing drift detection for one run is a much better failure mode
        than a monitoring job that stops running entirely. A symlink or a FIFO at
        the path is a different thing entirely and raises — see
        :meth:`_read_bytes`.
        """
        if self._loaded:
            return self._snapshots

        self._loaded = True
        raw_bytes = self._read_bytes()
        if raw_bytes is None:
            log.info("no existing state at %s; this run establishes the baseline", self.path)
            return self._snapshots

        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("ignoring unreadable state file %s: %s", self.path, exc)
            return self._snapshots

        if not isinstance(raw, dict):
            log.warning("ignoring malformed state file %s: root is not an object", self.path)
            return self._snapshots

        version = raw.get("version")
        if version != STATE_VERSION:
            log.warning(
                "state file %s has version %r (expected %d); ignoring and rebuilding baseline",
                self.path,
                version,
                STATE_VERSION,
            )
            return self._snapshots

        snapshots_raw = raw.get("snapshots")
        if not isinstance(snapshots_raw, dict):
            return self._snapshots

        for domain, payload in snapshots_raw.items():
            try:
                self._snapshots[str(domain)] = Snapshot.from_dict(payload)
            except (ValueError, TypeError) as exc:
                log.warning("skipping malformed snapshot for %s: %s", domain, exc)

        log.info("loaded baseline for %d domain(s) from %s", len(self._snapshots), self.path)
        return self._snapshots

    def get(self, domain: str) -> Snapshot | None:
        return self.load().get(domain)

    def save(self, snapshots: list[Snapshot]) -> None:
        """Persist *snapshots*, merging over any existing baseline.

        Merging rather than replacing means removing a domain from the config
        for one run does not discard its history.
        """
        merged = dict(self.load())
        for snapshot in snapshots:
            merged[snapshot.domain] = snapshot

        payload: dict[str, Any] = {
            "version": STATE_VERSION,
            "snapshots": {domain: snap.to_dict() for domain, snap in sorted(merged.items())},
        }

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StateError(f"cannot create state directory {self.path.parent}: {exc}") from exc

        serialized = json.dumps(payload, indent=2, ensure_ascii=False)

        # Write to a temp file in the *same* directory so os.replace is a true
        # atomic rename rather than a cross-filesystem copy.
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=".dnsdrift-state-", suffix=".tmp", dir=str(self.path.parent)
        )
        try:
            # Through the descriptor, before anything is written to it. chmod by
            # path names the file a second time, and between mkstemp and that
            # second lookup the name can be something else.
            os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        except OSError as exc:
            raise StateError(f"cannot write state file {self.path}: {exc}") from exc
        finally:
            # On success os.replace already consumed the temp file; this only
            # fires when the write failed partway and left one behind.
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)

        self._snapshots = merged
        log.info("saved baseline for %d domain(s) to %s", len(merged), self.path)
