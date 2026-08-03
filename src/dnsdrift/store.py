"""Snapshot persistence.

The state file is the tool's memory: without it every run looks like a first
run and no drift is ever detected. It is written atomically (temp file in the
same directory, then ``os.replace``) so an interrupted run cannot leave a
truncated file that silently wipes the baseline.

The file is created ``0600``. It contains an inventory of your domains, mail
routing and certificate details — not secrets, but not something to leave
world-readable on a shared host either.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
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


class StateError(Exception):
    """The state file could not be read or written."""


class SnapshotStore:
    """Reads and writes the previous-scan baseline."""

    def __init__(self, path: str | Path = DEFAULT_STATE_PATH) -> None:
        self.path = Path(path).expanduser()
        self._snapshots: dict[str, Snapshot] = {}
        self._loaded = False

    def load(self) -> dict[str, Snapshot]:
        """Load the baseline, returning an empty mapping if none exists.

        A corrupt state file is treated as "no baseline" rather than a fatal
        error: losing drift detection for one run is a much better failure mode
        than a monitoring job that stops running entirely.
        """
        if self._loaded:
            return self._snapshots

        self._loaded = True
        if not self.path.exists():
            log.info("no existing state at %s; this run establishes the baseline", self.path)
            return self._snapshots

        try:
            size = self.path.stat().st_size
            if size > _MAX_STATE_BYTES:
                raise StateError(f"state file is implausibly large ({size} bytes)")
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, StateError) as exc:
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
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
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
