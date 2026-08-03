"""Email authentication checks: SPF, DMARC, DKIM, MX.

These are the highest-signal checks in the tool. A DMARC policy quietly moving
from ``p=reject`` to ``p=none`` re-opens a domain to direct-from spoofing and
produces no error anywhere — nothing breaks, mail keeps flowing, and the change
is invisible until someone is phished.
"""

from __future__ import annotations

import re

from ..models import CheckResult, Finding, FindingKind, Severity
from ..resolver import DNSError
from .base import CheckContext, register

RFC_SPF = "https://www.rfc-editor.org/rfc/rfc7208"
RFC_DMARC = "https://www.rfc-editor.org/rfc/rfc7489"
RFC_DKIM = "https://www.rfc-editor.org/rfc/rfc6376"

# Mechanisms that cost a DNS lookup. RFC 7208 §4.6.4 caps these at 10; exceed
# it and conforming receivers return permerror, which in practice means SPF
# silently stops working.
_SPF_LOOKUP_LIMIT = 10


def _error(check: str, domain: str, message: str) -> CheckResult:
    """Represent an infrastructure failure as a finding, not a crash.

    An unreachable resolver must never be reported as "no DMARC record" — that
    is a false positive that trains people to ignore the tool. It surfaces as
    an explicit operational finding instead.
    """
    return CheckResult(
        check=check,
        domain=domain,
        error=message,
        findings=[
            Finding(
                domain=domain,
                check=check,
                kind=FindingKind.OPERATIONAL,
                severity=Severity.LOW,
                title=f"{check} check could not complete",
                detail=message,
                remediation="Re-run the scan. If it persists, check resolver reachability.",
            )
        ],
    )


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------


@register("spf")
def check_spf(ctx: CheckContext) -> CheckResult:
    domain = ctx.name
    try:
        answer = ctx.resolver.txt(domain)
    except DNSError as exc:
        return _error("spf", domain, str(exc))

    records = [r for r in answer.records if r.lower().startswith("v=spf1")]
    observations: dict[str, object] = {
        "record_count": len(records),
        "record": records[0] if len(records) == 1 else None,
        "records": records,
    }
    findings: list[Finding] = []

    if not records:
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="No SPF record",
                detail=(
                    f"{domain} publishes no v=spf1 TXT record, so receivers have no "
                    "authorised-sender list to check against."
                ),
                remediation=(
                    "Publish an SPF record listing every legitimate sending source, "
                    "ending in -all once you have confirmed the list is complete."
                ),
                references=(RFC_SPF,),
            )
        )
        return CheckResult(check="spf", domain=domain, observations=observations, findings=findings)

    if len(records) > 1:
        # RFC 7208 §4.5: more than one SPF record is a permerror. Receivers
        # discard both, so the domain is effectively unprotected.
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="Multiple SPF records",
                detail=(
                    f"{domain} publishes {len(records)} v=spf1 records. RFC 7208 requires "
                    "exactly one; receivers treat this as a permanent error and ignore SPF entirely."
                ),
                remediation="Merge the records into a single v=spf1 TXT record.",
                evidence={"records": records},
                references=(RFC_SPF,),
            )
        )

    record = records[0]
    terms = record.split()
    all_term = next((t for t in terms if t.lower().lstrip("+-~?").rstrip() == "all"), None)
    qualifier = all_term[0] if all_term and all_term[0] in "+-~?" else ("+" if all_term else None)

    observations["all_qualifier"] = qualifier
    lookups = _count_spf_lookups(terms)
    observations["dns_lookups"] = lookups

    if all_term is None:
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title="SPF record has no 'all' mechanism",
                detail=(
                    "Without a terminating all mechanism the record neither fails nor softfails "
                    "unlisted senders, leaving the outcome to receiver discretion."
                ),
                remediation="Append -all (or ~all during rollout) to the SPF record.",
                evidence={"record": record},
                references=(RFC_SPF,),
            )
        )
    elif qualifier == "+":
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.CRITICAL,
                title="SPF permits all senders (+all)",
                detail=(
                    "The record ends in +all, which explicitly authorises every host on the "
                    "internet to send as this domain. This is worse than having no SPF record."
                ),
                remediation="Replace +all with -all immediately.",
                evidence={"record": record},
                references=(RFC_SPF,),
            )
        )
    elif qualifier == "?":
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title="SPF policy is neutral (?all)",
                detail="?all expresses no opinion about unlisted senders, so SPF provides no protection.",
                remediation="Move to ~all, then to -all once the sender list is verified.",
                evidence={"record": record},
                references=(RFC_SPF,),
            )
        )

    if lookups > _SPF_LOOKUP_LIMIT:
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"SPF exceeds the 10 DNS-lookup limit ({lookups})",
                detail=(
                    f"The record requires approximately {lookups} DNS lookups to evaluate. "
                    "RFC 7208 caps this at 10; over the limit, conforming receivers return "
                    "permerror and SPF stops being enforced."
                ),
                remediation=(
                    "Flatten or remove include: mechanisms, or consolidate senders behind a "
                    "single relay. Note this count is static and does not expand nested includes."
                ),
                evidence={"record": record, "approximate_lookups": lookups},
                references=(RFC_SPF,),
            )
        )
    elif lookups >= _SPF_LOOKUP_LIMIT - 1:
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title=f"SPF is close to the DNS-lookup limit ({lookups}/10)",
                detail="Adding one more sender is likely to break SPF evaluation.",
                remediation="Reduce include: depth before onboarding another sending platform.",
                evidence={"record": record},
                references=(RFC_SPF,),
            )
        )

    if any(t.lower().startswith("ptr") for t in terms):
        findings.append(
            Finding(
                domain=domain,
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title="SPF uses the deprecated ptr mechanism",
                detail="RFC 7208 §5.5 deprecates ptr; it is slow and some receivers ignore it.",
                remediation="Replace ptr with explicit ip4/ip6 or include mechanisms.",
                evidence={"record": record},
                references=(RFC_SPF,),
            )
        )

    return CheckResult(check="spf", domain=domain, observations=observations, findings=findings)


def _count_spf_lookups(terms: list[str]) -> int:
    """Approximate the DNS-lookup count of an SPF record.

    Counts only mechanisms present in this record. Resolving nested includes
    would give an exact number but costs a lookup per include and can be turned
    into an amplification vector by a hostile record, so the tool deliberately
    under-reports rather than chasing them.
    """
    count = 0
    for term in terms:
        bare = term.lstrip("+-~?").lower()
        if (
            bare.startswith(("include:", "exists:", "redirect="))
            or bare == "a"
            or bare.startswith(("a:", "a/"))
            or bare == "mx"
            or bare.startswith(("mx:", "mx/"))
            or bare.startswith("ptr")
        ):
            count += 1
    return count


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

_DMARC_TAG_RE = re.compile(r"^\s*([a-z]+)\s*=\s*(.*?)\s*$", re.IGNORECASE)


@register("dmarc")
def check_dmarc(ctx: CheckContext) -> CheckResult:
    domain = ctx.name
    qname = f"_dmarc.{domain}"
    try:
        answer = ctx.resolver.txt(qname)
    except DNSError as exc:
        return _error("dmarc", domain, str(exc))

    records = [r for r in answer.records if r.lower().replace(" ", "").startswith("v=dmarc1")]
    observations: dict[str, object] = {"record_count": len(records), "record": None, "tags": {}}
    findings: list[Finding] = []

    if not records:
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="No DMARC record",
                detail=(
                    f"No DMARC record at {qname}. Without one, receivers have no instruction "
                    "for handling mail that fails SPF and DKIM, and you receive no visibility "
                    "reports about who is sending as your domain."
                ),
                remediation=(
                    'Publish "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain" to begin '
                    "collecting reports, then move to p=quarantine and p=reject."
                ),
                references=(RFC_DMARC,),
            )
        )
        return CheckResult(check="dmarc", domain=domain, observations=observations, findings=findings)

    if len(records) > 1:
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="Multiple DMARC records",
                detail=(
                    "RFC 7489 §6.6.3 requires receivers to ignore the domain's DMARC policy "
                    "entirely when more than one record is published."
                ),
                remediation="Remove the extra _dmarc TXT records, keeping exactly one.",
                evidence={"records": records},
                references=(RFC_DMARC,),
            )
        )

    record = records[0]
    tags = _parse_dmarc_tags(record)
    observations["record"] = record
    observations["tags"] = tags

    policy = tags.get("p", "").lower()
    subdomain_policy = tags.get("sp", "").lower()
    pct_raw = tags.get("pct", "100")

    if policy in ("", "none"):
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH if policy == "none" else Severity.CRITICAL,
                title=f"DMARC policy is {'p=none' if policy == 'none' else 'missing'}",
                detail=(
                    "p=none is monitor-only: failing mail is still delivered. Spoofed mail "
                    "claiming to be from this domain reaches inboxes."
                    if policy == "none"
                    else "The record has no p= tag, which makes it invalid and unenforced."
                ),
                remediation="Move to p=quarantine, then p=reject, once report data confirms legitimate senders pass.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )
    elif policy == "quarantine":
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title="DMARC policy is p=quarantine, not p=reject",
                detail="Failing mail lands in spam rather than being rejected outright.",
                remediation="Move to p=reject once quarantine has run cleanly.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )
    elif policy != "reject":
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title=f"DMARC policy value is invalid (p={policy})",
                detail="Only none, quarantine and reject are valid; receivers ignore anything else.",
                remediation="Correct the p= tag.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )

    if subdomain_policy == "none" and policy in ("quarantine", "reject"):
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title="Subdomain policy weakens the parent (sp=none)",
                detail=(
                    f"The domain enforces p={policy} but sp=none exempts every subdomain, "
                    "so an attacker can spoof any.subdomain of this domain freely."
                ),
                remediation="Set sp=reject, or remove sp= so subdomains inherit the parent policy.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )

    try:
        pct = int(pct_raw)
    except (TypeError, ValueError):
        pct = 100
    observations["pct"] = pct
    if policy in ("quarantine", "reject") and pct < 100:
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title=f"DMARC applies to only {pct}% of mail",
                detail=f"pct={pct} means {100 - pct}% of failing mail bypasses the policy entirely.",
                remediation="Raise pct to 100 once rollout is complete.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )

    if not tags.get("rua"):
        findings.append(
            Finding(
                domain=domain,
                check="dmarc",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title="No DMARC aggregate report address (rua)",
                detail="Without rua you get no visibility into who is sending as your domain.",
                remediation="Add rua=mailto:dmarc@yourdomain to the record.",
                evidence={"record": record},
                references=(RFC_DMARC,),
            )
        )

    return CheckResult(check="dmarc", domain=domain, observations=observations, findings=findings)


def _parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        match = _DMARC_TAG_RE.match(part)
        if match:
            tags[match.group(1).lower()] = match.group(2)
    return tags


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------


@register("dkim")
def check_dkim(ctx: CheckContext) -> CheckResult:
    """Probe well-known DKIM selectors.

    DKIM has no discovery mechanism: you cannot enumerate a domain's selectors,
    only guess them. So "no selectors found" is reported at INFO, never as a
    failure — a domain may well be signing with a selector this list does not
    include. What *is* actionable is a selector that used to answer and no
    longer does, which the drift engine catches.
    """
    domain = ctx.name
    found: dict[str, dict[str, object]] = {}
    findings: list[Finding] = []
    errors = 0

    for selector in ctx.domain.dkim_selectors:
        qname = f"{selector}._domainkey.{domain}"
        try:
            answer = ctx.resolver.txt(qname)
        except DNSError:
            errors += 1
            continue

        record = next((r for r in answer.records if "p=" in r.lower() or "v=dkim1" in r.lower()), None)
        if record is None:
            continue

        key_material = _dkim_public_key(record)
        entry: dict[str, object] = {
            "present": True,
            "revoked": key_material == "",
            "key_type": _dkim_tag(record, "k") or "rsa",
            "key_length_b64": len(key_material) if key_material else 0,
        }
        found[selector] = entry

        if key_material == "":
            # An empty p= tag is the RFC 6376 way to revoke a key. Seeing one
            # is usually intentional, but a forgotten revoked selector left in
            # DNS is a loose end worth flagging.
            findings.append(
                Finding(
                    domain=domain,
                    check="dkim",
                    kind=FindingKind.POSTURE,
                    severity=Severity.LOW,
                    title=f"DKIM selector '{selector}' is revoked (empty p=)",
                    detail="The selector still exists in DNS but publishes no key material.",
                    remediation="Remove the record if the selector is retired.",
                    evidence={"selector": selector},
                    references=(RFC_DKIM,),
                )
            )
        elif key_material is None:
            # v=DKIM1 with no p= tag at all. Malformed rather than revoked:
            # receivers cannot verify a signature against it.
            findings.append(
                Finding(
                    domain=domain,
                    check="dkim",
                    kind=FindingKind.POSTURE,
                    severity=Severity.MEDIUM,
                    title=f"DKIM selector '{selector}' has no p= tag",
                    detail=(
                        "The record exists but omits the public key tag entirely, so it is "
                        "malformed and signatures made with this selector cannot be verified."
                    ),
                    remediation="Republish the selector with a valid p= public key, or remove it.",
                    evidence={"selector": selector},
                    references=(RFC_DKIM,),
                )
            )
        elif entry["key_type"] == "rsa" and len(key_material) < 216:
            # A 1024-bit RSA SubjectPublicKeyInfo base64-encodes to ~216 chars;
            # anything shorter is a weak key.
            findings.append(
                Finding(
                    domain=domain,
                    check="dkim",
                    kind=FindingKind.POSTURE,
                    severity=Severity.MEDIUM,
                    title=f"DKIM selector '{selector}' appears to use a weak RSA key",
                    detail=(
                        "The published key is shorter than a 1024-bit RSA key. Keys below "
                        "1024 bits are considered forgeable and some receivers reject them."
                    ),
                    remediation="Rotate to a 2048-bit RSA key.",
                    evidence={"selector": selector, "encoded_length": len(key_material)},
                    references=(RFC_DKIM,),
                )
            )

    observations: dict[str, object] = {
        "selectors_probed": list(ctx.domain.dkim_selectors),
        "selectors_found": sorted(found),
        "details": found,
    }

    if not found:
        findings.append(
            Finding(
                domain=domain,
                check="dkim",
                kind=FindingKind.POSTURE,
                severity=Severity.INFO,
                title="No DKIM selectors found among common names",
                detail=(
                    "None of the probed selectors answered. DKIM selectors cannot be enumerated, "
                    "so this does not prove the domain is unsigned — add your real selectors to "
                    "the config to monitor them."
                ),
                remediation="Set dkim_selectors for this domain in your config.",
                evidence={"probed": list(ctx.domain.dkim_selectors)},
                references=(RFC_DKIM,),
            )
        )

    result = CheckResult(check="dkim", domain=domain, observations=observations, findings=findings)
    if errors and not found:
        result.error = f"{errors} DKIM selector lookups failed"
    return result


def _dkim_tag(record: str, tag: str) -> str | None:
    for part in record.split(";"):
        chunk = part.strip()
        if chunk.lower().startswith(f"{tag}="):
            return chunk[len(tag) + 1 :].strip()
    return None


def _dkim_public_key(record: str) -> str | None:
    value = _dkim_tag(record, "p")
    if value is None:
        return None
    return value.replace(" ", "")


# --------------------------------------------------------------------------
# MX
# --------------------------------------------------------------------------


@register("mx")
def check_mx(ctx: CheckContext) -> CheckResult:
    domain = ctx.name
    try:
        answer = ctx.resolver.query(domain, "MX")
    except DNSError as exc:
        return _error("mx", domain, str(exc))

    hosts = tuple(sorted(answer.records))
    null_mx = hosts == ("0 .",) or any(r.strip().endswith(" .") and r.strip().startswith("0") for r in hosts)

    observations: dict[str, object] = {
        "records": list(hosts),
        "count": len(hosts),
        "null_mx": null_mx,
    }
    findings: list[Finding] = []

    if not hosts:
        # No MX is only a problem if the domain is *supposed* to receive mail,
        # which the tool cannot know. Reported at INFO so it shows up in drift
        # (MX disappearing is a real incident) without crying wolf.
        findings.append(
            Finding(
                domain=domain,
                check="mx",
                kind=FindingKind.POSTURE,
                severity=Severity.INFO,
                title="No MX records",
                detail=(
                    f"{domain} publishes no MX records and does not accept mail. If this domain "
                    "is not meant to receive mail, publish a null MX (0 .) to state that explicitly."
                ),
                remediation='Publish "0 ." as the MX record for non-mail domains (RFC 7505).',
                references=("https://www.rfc-editor.org/rfc/rfc7505",),
            )
        )

    return CheckResult(check="mx", domain=domain, observations=observations, findings=findings)
