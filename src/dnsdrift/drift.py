"""Snapshot diffing — the part that turns a scanner into a monitor.

A posture check tells you a domain is weak today. Drift tells you it *became*
weak, and roughly when. That distinction is what makes the tool worth running
on a schedule: the second run onward, every finding here corresponds to
something a human changed, on purpose or by accident, since the last run.

Two design rules keep this from becoming a noise generator:

1. **Only meaningful transitions are reported.** A DMARC policy moving
   ``reject -> none`` is a high-severity downgrade; ``none -> reject`` is an
   improvement and is reported at INFO. Nobody needs an alert because their
   posture got better, but the record is useful for audit.

2. **Nothing non-deterministic is diffed.** Checks sort their observations and
   omit values that change every run (timestamps, per-renewal certificate
   lists). Any field that legitimately varies run-to-run must be excluded here
   or it will generate a finding on every single scan and get muted within a
   week.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from .models import Finding, FindingKind, Severity, Snapshot

log = logging.getLogger(__name__)

# DMARC enforcement strength, for detecting downgrades.
_DMARC_STRENGTH = {"": 0, "none": 1, "quarantine": 2, "reject": 3}

# SPF 'all' qualifier strength. The empty string means the record has no `all`
# mechanism at all, which RFC 7208 §4.7 evaluates as neutral — the same
# effective strength as ?all. Excluding it would let "-all" -> "no all" pass as
# a cosmetic change when it is a real weakening.
_SPF_STRENGTH = {"": 1, "+": 0, "?": 1, "~": 2, "-": 3}

DriftRule = Callable[[str, dict[str, Any], dict[str, Any]], list[Finding]]

_RULES: dict[str, DriftRule] = {}


def rule(check: str) -> Callable[[DriftRule], DriftRule]:
    def decorator(func: DriftRule) -> DriftRule:
        _RULES[check] = func
        return func

    return decorator


def diff_snapshots(previous: Snapshot | None, current: Snapshot) -> list[Finding]:
    """Compare two snapshots of the same domain and return drift findings.

    Returns an empty list when there is no baseline — a first run has nothing
    to compare against, and inventing findings there would misrepresent them as
    changes.
    """
    if previous is None:
        return []
    if previous.domain != current.domain:
        raise ValueError(
            f"cannot diff snapshots for different domains: {previous.domain} vs {current.domain}"
        )

    findings: list[Finding] = []
    for check, current_obs in sorted(current.checks.items()):
        previous_obs = previous.checks.get(check)
        if previous_obs is None:
            # The check did not run last time (newly enabled, or it errored).
            # Absence of a baseline is not drift.
            continue
        handler = _RULES.get(check)
        if handler is None:
            continue
        try:
            findings.extend(handler(current.domain, previous_obs, current_obs))
        except (AttributeError, KeyError, TypeError, ValueError):
            # A malformed historical snapshot must not abort the whole scan.
            # AttributeError is included deliberately: a hand-edited or
            # older-format state file can hold a string where a mapping is
            # expected, and .get() on it would otherwise kill the run.
            log.warning("skipping drift comparison for %s/%s: malformed baseline", current.domain, check)
            continue

    return findings


def _drift(
    domain: str,
    check: str,
    severity: Severity,
    title: str,
    detail: str,
    remediation: str = "",
    evidence: dict[str, Any] | None = None,
) -> Finding:
    return Finding(
        domain=domain,
        check=check,
        kind=FindingKind.DRIFT,
        severity=severity,
        title=title,
        detail=detail,
        remediation=remediation,
        evidence=evidence or {},
    )


@rule("dmarc")
def _dmarc_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    old_tags = old.get("tags") or {}
    new_tags = new.get("tags") or {}
    old_policy = str(old_tags.get("p", "")).lower()
    new_policy = str(new_tags.get("p", "")).lower()

    old_strength = _DMARC_STRENGTH.get(old_policy, 0)
    new_strength = _DMARC_STRENGTH.get(new_policy, 0)

    if old.get("record") and not new.get("record"):
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.CRITICAL,
                "DMARC record was removed",
                f"{domain} had a DMARC record on the previous scan and now has none. "
                "The domain is fully exposed to direct-from spoofing.",
                "Restore the DMARC record and investigate who removed it.",
                {"previous_record": old.get("record")},
            )
        )
    elif new_strength < old_strength:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.CRITICAL if new_policy == "none" else Severity.HIGH,
                f"DMARC policy downgraded: p={old_policy or 'unset'} -> p={new_policy or 'unset'}",
                f"Enforcement on {domain} was weakened. Mail failing authentication that would "
                "previously have been rejected or quarantined is now more likely to be delivered.",
                "Confirm this was an intentional, approved change; otherwise restore the previous policy.",
                {"previous": old_policy, "current": new_policy},
            )
        )
    elif new_strength > old_strength:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.INFO,
                f"DMARC policy strengthened: p={old_policy or 'unset'} -> p={new_policy}",
                "Enforcement was tightened.",
                "",
                {"previous": old_policy, "current": new_policy},
            )
        )

    old_count = _as_int(old.get("record_count"), 0)
    new_count = _as_int(new.get("record_count"), 0)
    if new_count > 1 >= old_count:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.HIGH,
                f"DMARC went from {old_count} record to {new_count}",
                "RFC 7489 §6.6.3 requires receivers to ignore the domain's DMARC policy "
                "entirely when more than one record is published.",
                "Remove the extra _dmarc TXT records, keeping exactly one.",
                {"previous": old_count, "current": new_count},
            )
        )

    old_pct = _as_int(old.get("pct"), 100)
    new_pct = _as_int(new.get("pct"), 100)
    if new_pct < old_pct:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.MEDIUM,
                f"DMARC sampling rate reduced: pct={old_pct} -> pct={new_pct}",
                f"Only {new_pct}% of failing mail is now subject to the policy.",
                "Restore pct=100 unless this is a deliberate, time-boxed rollout step.",
                {"previous": old_pct, "current": new_pct},
            )
        )

    record_removed = bool(old.get("record")) and not new.get("record")

    old_rua = str(old_tags.get("rua", ""))
    new_rua = str(new_tags.get("rua", ""))
    if record_removed:
        # The CRITICAL "record was removed" finding above already covers this;
        # a second MEDIUM about the reporting address is just noise.
        pass
    elif old_rua and not new_rua:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.MEDIUM,
                "DMARC aggregate reporting address (rua) was removed",
                "You will no longer receive reports about who is sending as this domain.",
                "Restore the rua= tag.",
                {"previous": old_rua},
            )
        )
    elif old_rua and new_rua and old_rua != new_rua:
        findings.append(
            _drift(
                domain,
                "dmarc",
                Severity.MEDIUM,
                "DMARC reporting address changed",
                f"rua changed from {old_rua} to {new_rua}. Redirecting DMARC reports is a way "
                "to hide spoofing activity from the domain owner.",
                "Confirm the new address is one you control.",
                {"previous": old_rua, "current": new_rua},
            )
        )

    return findings


@rule("spf")
def _spf_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    old_record = old.get("record")
    new_record = new.get("record")

    if old_record and not new_record and not new.get("records"):
        findings.append(
            _drift(
                domain,
                "spf",
                Severity.HIGH,
                "SPF record was removed",
                f"{domain} previously published an SPF record and now publishes none.",
                "Restore the SPF record and investigate the change.",
                {"previous_record": old_record},
            )
        )
        return findings

    old_qualifier = str(old.get("all_qualifier") or "")
    new_qualifier = str(new.get("all_qualifier") or "")
    old_strength = _SPF_STRENGTH.get(old_qualifier, -1)
    new_strength = _SPF_STRENGTH.get(new_qualifier, -1)

    # A record terminating in redirect= has no `all` by design, so comparing
    # qualifiers across a redirect boundary would be meaningless.
    redirect_involved = bool(old.get("redirect")) or bool(new.get("redirect"))

    if not redirect_involved and old_strength >= 0 and new_strength >= 0 and new_strength < old_strength:
        findings.append(
            _drift(
                domain,
                "spf",
                Severity.CRITICAL if new_qualifier == "+" else Severity.HIGH,
                f"SPF policy weakened: {old_qualifier or 'no '}all -> {new_qualifier or 'no '}all",
                f"The SPF terminating mechanism on {domain} became more permissive.",
                "Confirm the change was intentional; restore the stricter qualifier otherwise.",
                {"previous": f"{old_qualifier}all", "current": f"{new_qualifier}all"},
            )
        )

    old_lookups = _as_int(old.get("dns_lookups"), 0)
    new_lookups = _as_int(new.get("dns_lookups"), 0)
    if new_lookups > 10 >= old_lookups:
        findings.append(
            _drift(
                domain,
                "spf",
                Severity.HIGH,
                f"SPF crossed the 10 DNS-lookup limit ({old_lookups} -> {new_lookups})",
                "SPF evaluation now returns permerror at conforming receivers, so SPF has "
                "effectively stopped working for this domain.",
                "Reduce include: mechanisms below the limit.",
                {"previous": old_lookups, "current": new_lookups},
            )
        )

    old_count = _as_int(old.get("record_count"), 0)
    new_count = _as_int(new.get("record_count"), 0)
    if new_count > 1 >= old_count:
        findings.append(
            _drift(
                domain,
                "spf",
                Severity.HIGH,
                f"SPF went from {old_count} record to {new_count}",
                "RFC 7208 §4.5 requires exactly one v=spf1 record. With more than one, "
                "receivers return permerror and stop evaluating SPF for this domain entirely.",
                "Merge the records back into a single v=spf1 TXT record.",
                {"previous": old_count, "current": new_count},
            )
        )

    if old_record and new_record and old_record != new_record:
        findings.append(
            _drift(
                domain,
                "spf",
                Severity.LOW,
                "SPF record changed",
                "The SPF record content changed since the previous scan.",
                "Confirm every newly authorised sender is legitimate.",
                {"previous": old_record, "current": new_record},
            )
        )

    return findings


@rule("dkim")
def _dkim_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    old_found = set(old.get("selectors_found") or [])
    new_found = set(new.get("selectors_found") or [])

    # A selector whose lookup failed on either side is indeterminate, not
    # absent. Comparing it would report a timeout as "your DKIM key vanished".
    indeterminate = set(old.get("selectors_errored") or []) | set(new.get("selectors_errored") or [])

    removed = sorted(old_found - new_found - indeterminate)
    added = sorted(new_found - old_found - indeterminate)

    if removed:
        findings.append(
            _drift(
                domain,
                "dkim",
                Severity.MEDIUM,
                f"DKIM selector(s) disappeared: {', '.join(removed)}",
                "Mail signed with these selectors will now fail DKIM verification, which can "
                "in turn cause DMARC failures and delivery loss.",
                "Confirm the selectors were intentionally retired and that no sender still uses them.",
                {"removed": removed},
            )
        )

    if added:
        findings.append(
            _drift(
                domain,
                "dkim",
                Severity.LOW,
                f"New DKIM selector(s) published: {', '.join(added)}",
                "A new signing key appeared. This is normal during key rotation or when "
                "onboarding a mail platform — and is also what an attacker who gained DNS "
                "access would do to sign mail as you.",
                "Confirm the new selectors correspond to a change you made.",
                {"added": added},
            )
        )

    old_details = old.get("details") or {}
    new_details = new.get("details") or {}
    for selector in sorted((old_found & new_found) - indeterminate):
        old_entry = old_details.get(selector) or {}
        new_entry = new_details.get(selector) or {}
        if not old_entry.get("revoked") and new_entry.get("revoked"):
            findings.append(
                _drift(
                    domain,
                    "dkim",
                    Severity.MEDIUM,
                    f"DKIM selector '{selector}' was revoked",
                    "The selector now publishes an empty key, so signatures made with it no longer verify.",
                    "Confirm the revocation was intentional.",
                    {"selector": selector},
                )
            )

    return findings


@rule("mx")
def _mx_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    old_records = sorted(old.get("records") or [])
    new_records = sorted(new.get("records") or [])
    if old_records == new_records:
        return []

    if old_records and not new_records:
        return [
            _drift(
                domain,
                "mx",
                Severity.HIGH,
                "All MX records were removed",
                f"{domain} no longer accepts mail. If unintentional, inbound mail is being lost now.",
                "Restore the MX records immediately.",
                {"previous": old_records},
            )
        ]

    return [
        _drift(
            domain,
            "mx",
            Severity.HIGH,
            "MX records changed",
            f"Mail routing for {domain} changed. An unauthorised MX change redirects inbound "
            "mail — including password resets — to an attacker.",
            "Confirm this was an approved mail platform change.",
            {"previous": old_records, "current": new_records},
        )
    ]


@rule("dnssec")
def _dnssec_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    was_signed = bool(old.get("signed"))
    is_signed = bool(new.get("signed"))

    if was_signed and not is_signed:
        return [
            _drift(
                domain,
                "dnssec",
                Severity.HIGH,
                "DNSSEC was disabled",
                f"The DS record for {domain} disappeared. DNS answers are no longer "
                "cryptographically validated and can be forged.",
                "Confirm this was an intentional change; re-publish the DS record otherwise.",
                {},
            )
        ]
    if is_signed and not was_signed:
        return [
            _drift(
                domain,
                "dnssec",
                Severity.INFO,
                "DNSSEC was enabled",
                "A DS record is now published at the parent zone.",
                "",
                {},
            )
        ]
    return []


@rule("caa")
def _caa_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    old_records = sorted(old.get("records") or [])
    new_records = sorted(new.get("records") or [])

    if old_records and not new_records:
        findings.append(
            _drift(
                domain,
                "caa",
                Severity.MEDIUM,
                "CAA records were removed",
                f"{domain} no longer restricts which CAs may issue certificates for it.",
                "Restore the CAA record set.",
                {"previous": old_records},
            )
        )
        return findings

    old_issuers = set(old.get("issuers") or [])
    new_issuers = set(new.get("issuers") or [])
    added = sorted(new_issuers - old_issuers)
    if added:
        findings.append(
            _drift(
                domain,
                "caa",
                Severity.MEDIUM,
                f"New certificate authority authorised: {', '.join(added)}",
                "A CA was added to the CAA record set. Adding a CA is a prerequisite for "
                "issuing a certificate for this domain through that CA.",
                "Confirm the addition was requested by someone authorised to make it.",
                {"added": added},
            )
        )
    return findings


@rule("cname")
def _cname_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    # Names we could not resolve on either side are unknown, not changed.
    indeterminate = set(old.get("unresolved") or []) | set(new.get("unresolved") or [])

    old_dangling = set(old.get("dangling") or [])
    new_dangling = set(new.get("dangling") or [])
    newly_dangling = sorted(new_dangling - old_dangling - indeterminate)
    if newly_dangling:
        findings.append(
            _drift(
                domain,
                "cname",
                Severity.CRITICAL,
                f"New dangling CNAME(s): {', '.join(newly_dangling)}",
                "These names now point at targets that do not resolve, making them candidates "
                "for subdomain takeover. A newly-dangling record usually means a service was "
                "just decommissioned without cleaning up DNS.",
                "Remove the CNAME records or re-claim the targets.",
                {"names": newly_dangling},
            )
        )

    old_cnames = old.get("cnames") or {}
    new_cnames = new.get("cnames") or {}
    retargeted = [
        name for name in sorted(set(old_cnames) & set(new_cnames)) if old_cnames[name] != new_cnames[name]
    ]
    if retargeted:
        findings.append(
            _drift(
                domain,
                "cname",
                Severity.MEDIUM,
                f"CNAME target changed for {', '.join(retargeted)}",
                "A subdomain now points somewhere new.",
                "Confirm the new targets are yours.",
                {
                    "changes": {
                        name: {"previous": old_cnames[name], "current": new_cnames[name]}
                        for name in retargeted
                    }
                },
            )
        )

    return findings


@rule("tls")
def _tls_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    if old.get("reachable") and not new.get("reachable"):
        findings.append(
            _drift(
                domain,
                "tls",
                Severity.MEDIUM,
                "HTTPS service stopped responding",
                f"{old.get('host', domain)} answered a TLS handshake on the previous scan and does not now.",
                "Check whether the service is down or was decommissioned.",
                {},
            )
        )
        return findings

    old_issuer = str(old.get("issuer") or "")
    new_issuer = str(new.get("issuer") or "")
    if old_issuer and new_issuer and old_issuer != new_issuer:
        findings.append(
            _drift(
                domain,
                "tls",
                Severity.MEDIUM,
                "TLS certificate issuer changed",
                f"The certificate is now issued by {new_issuer} instead of {old_issuer}. "
                "An unexpected issuer change can indicate a certificate obtained by someone else.",
                "Confirm the CA change was intentional.",
                {"previous": old_issuer, "current": new_issuer},
            )
        )

    old_names = set(old.get("subject_alt_names") or [])
    new_names = set(new.get("subject_alt_names") or [])
    added = sorted(new_names - old_names)
    if added and old_names:
        findings.append(
            _drift(
                domain,
                "tls",
                Severity.LOW,
                f"TLS certificate now covers additional names: {', '.join(added[:10])}",
                "New hostnames were added to the certificate.",
                "Confirm the added names are expected.",
                {"added": added[:50]},
            )
        )

    old_key_bits = _as_int(old.get("key_bits"), 0)
    new_key_bits = _as_int(new.get("key_bits"), 0)
    if old_key_bits and new_key_bits and new_key_bits < old_key_bits:
        findings.append(
            _drift(
                domain,
                "tls",
                Severity.MEDIUM,
                f"TLS key size decreased ({old_key_bits} -> {new_key_bits} bits)",
                "The deployed certificate uses a weaker key than before.",
                "Reissue with a key at least as strong as the previous one.",
                {"previous": old_key_bits, "current": new_key_bits},
            )
        )

    return findings


@rule("ct")
def _ct_drift(domain: str, old: dict[str, Any], new: dict[str, Any]) -> list[Finding]:
    if old.get("names_truncated") or new.get("names_truncated"):
        # The name list is a capped window, so a name can appear simply because
        # another certificate expired out of it. Reporting that as a new
        # hostname would be a false positive on every large domain.
        return []

    old_names = set(old.get("covered_names") or [])
    new_names = set(new.get("covered_names") or [])
    if not old_names:
        return []

    added = sorted(new_names - old_names)
    if not added:
        return []

    return [
        _drift(
            domain,
            "ct",
            Severity.MEDIUM,
            f"Certificates issued for {len(added)} previously unseen hostname(s)",
            "New hostnames under this domain appeared in Certificate Transparency logs. This is "
            "how unsanctioned deployments and impersonation infrastructure first become visible.",
            "Confirm each hostname belongs to a service you know about.",
            {"new_names": added[:50]},
        )
    ]


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
