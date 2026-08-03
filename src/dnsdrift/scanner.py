"""Scan orchestration.

Runs the configured checks across the configured domains with bounded
concurrency, folds the results into snapshots, diffs those against the stored
baseline, and returns a :class:`~dnsdrift.models.ScanReport`.

Concurrency is threads rather than asyncio: the work is DNS and socket I/O,
dnspython's synchronous API is the well-trodden path, and a bounded thread pool
is far easier to reason about when the failure mode you care about is "one
hostile domain hangs the scan".
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import __version__
from .checks import CheckContext, get_check
from .config import Config, DomainConfig
from .drift import diff_snapshots
from .models import CheckResult, Finding, ScanReport, Severity, Snapshot
from .resolver import Resolver
from .store import SnapshotStore

log = logging.getLogger(__name__)

# Findings are emitted in this order within a report so the most urgent items
# are read first regardless of which check produced them.
_SEVERITY_ORDER = {s: -s.rank for s in Severity}


def scan(config: Config, store: SnapshotStore | None = None) -> ScanReport:
    """Run a full scan and return the report."""
    started = Snapshot.now_iso()
    baseline_available = False

    resolver = Resolver(
        timeout=config.settings.timeout_seconds,
        retries=config.settings.dns_retries,
        nameservers=config.settings.resolvers,
    )

    snapshots: list[Snapshot] = []
    findings: list[Finding] = []
    checks_run = 0
    checks_failed = 0

    # One task per (domain, check) rather than per domain: a single domain with
    # nine checks would otherwise serialise onto one worker while others idle.
    tasks: list[tuple[DomainConfig, str]] = [
        (domain, check_name) for domain in config.domains for check_name in domain.checks
    ]

    results: dict[str, dict[str, CheckResult]] = {d.name: {} for d in config.domains}

    with ThreadPoolExecutor(max_workers=config.settings.max_workers) as pool:
        futures = {
            pool.submit(_run_check, domain, check_name, config, resolver): (domain, check_name)
            for domain, check_name in tasks
        }
        for future in as_completed(futures):
            domain, check_name = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - a crashing check must not kill the scan
                log.exception("check %s crashed for %s", check_name, domain.name)
                result = CheckResult(
                    check=check_name,
                    domain=domain.name,
                    error=f"internal error: {type(exc).__name__}: {exc}",
                )
            results[domain.name][check_name] = result

    for domain in config.domains:
        domain_results = results[domain.name]
        snapshot = Snapshot(domain=domain.name, collected_at=started)
        previous = store.get(domain.name) if store else None

        for check_name in domain.checks:
            outcome = domain_results.get(check_name)
            if outcome is None:
                continue
            checks_run += 1
            findings.extend(outcome.findings)
            if outcome.error:
                checks_failed += 1
                snapshot.errors[check_name] = outcome.error
            # A check that errored has unreliable observations. Recording them
            # would make the next run diff good data against bad and emit
            # phantom drift, so failed checks contribute nothing to the
            # snapshot and simply leave the previous baseline in place.
            if outcome.ok and outcome.observations:
                if outcome.partial and previous is not None:
                    # Layer the partial observation over the last known-good one
                    # so fields the check could not determine this run survive.
                    merged = dict(previous.checks.get(check_name, {}))
                    merged.update(outcome.observations)
                    snapshot.checks[check_name] = merged
                else:
                    snapshot.checks[check_name] = outcome.observations

        if previous is not None:
            baseline_available = True
            findings.extend(diff_snapshots(previous, snapshot))

        # Carry forward observations for checks that failed this run so a
        # transient resolver blip does not erase the baseline.
        if previous is not None:
            for check_name, observations in previous.checks.items():
                snapshot.checks.setdefault(check_name, observations)

        snapshots.append(snapshot)

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.domain, f.check, f.title))

    return ScanReport(
        started_at=started,
        finished_at=Snapshot.now_iso(),
        tool_version=__version__,
        snapshots=snapshots,
        findings=findings,
        baseline_available=baseline_available,
        checks_run=checks_run,
        checks_failed=checks_failed,
    )


def _run_check(domain: DomainConfig, check_name: str, config: Config, resolver: Resolver) -> CheckResult:
    check = get_check(check_name)
    ctx = CheckContext(domain=domain, settings=config.settings, resolver=resolver)
    log.debug("running %s for %s", check_name, domain.name)
    return check(ctx)
