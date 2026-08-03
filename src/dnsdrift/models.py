"""Core data model.

Everything the scanner produces flows through these types. They are plain
dataclasses on purpose: a security tool should be auditable without the reader
needing to understand a metaclass-driven validation framework.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity, ordered.

    The numeric ``rank`` is what comparisons and exit-code thresholds use;
    the string value is what humans and JSON consumers see.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {valid})") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingKind(str, Enum):
    """Why a finding exists.

    POSTURE findings describe the state of a domain right now ("no DMARC
    record"). DRIFT findings describe a *change* since the previous snapshot
    ("DMARC policy downgraded from reject to none"). Keeping them distinct
    matters: on a first run there is no baseline, so drift findings are
    impossible and posture findings are all you get.
    """

    POSTURE = "posture"
    DRIFT = "drift"
    OPERATIONAL = "operational"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single observation about a domain."""

    domain: str
    check: str
    kind: FindingKind
    severity: Severity
    title: str
    detail: str
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        """Stable ID for deduplication and alert suppression.

        Deliberately excludes ``detail`` and ``evidence`` so that a finding
        whose wording changes between versions is still recognised as the same
        underlying issue.
        """
        raw = f"{self.domain}|{self.check}|{self.kind.value}|{self.title}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        out["severity"] = self.severity.value
        out["references"] = list(self.references)
        out["fingerprint"] = self.fingerprint
        return out


@dataclass(slots=True)
class CheckResult:
    """What one check observed for one domain.

    ``observations`` is the part that gets persisted and diffed across runs, so
    it must be JSON-serialisable and deterministic — no timestamps, no set
    ordering, no object reprs. If a value is naturally unordered, sort it
    before putting it here, or every run will look like drift.
    """

    check: str
    domain: str
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(slots=True)
class Snapshot:
    """The full observed state of one domain at one point in time."""

    domain: str
    collected_at: str
    checks: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "collected_at": self.collected_at,
            "checks": self.checks,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Snapshot:
        if not isinstance(raw, dict):
            raise ValueError("snapshot must be an object")
        domain = raw.get("domain")
        if not isinstance(domain, str) or not domain:
            raise ValueError("snapshot is missing a domain")
        checks = raw.get("checks") or {}
        errors = raw.get("errors") or {}
        if not isinstance(checks, dict) or not isinstance(errors, dict):
            raise ValueError("snapshot checks/errors must be objects")
        return cls(
            domain=domain,
            collected_at=str(raw.get("collected_at") or ""),
            checks=checks,
            errors={str(k): str(v) for k, v in errors.items()},
        )


@dataclass(slots=True)
class ScanReport:
    """Everything one `dnsdrift scan` produced."""

    started_at: str
    finished_at: str
    tool_version: str
    snapshots: list[Snapshot] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    baseline_available: bool = False
    ai_summary: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "dnsdrift",
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "baseline_available": self.baseline_available,
            "domains_scanned": len(self.snapshots),
            "counts_by_severity": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "snapshots": [s.to_dict() for s in self.snapshots],
            "ai_summary": self.ai_summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False, ensure_ascii=False)
