"""DNS hygiene checks: DNSSEC, CAA, and dangling CNAME / subdomain takeover."""

from __future__ import annotations

from ..models import CheckResult, Finding, FindingKind, Severity
from ..resolver import DNSError
from .base import CheckContext, register

RFC_CAA = "https://www.rfc-editor.org/rfc/rfc8659"
RFC_DNSSEC = "https://www.rfc-editor.org/rfc/rfc4033"

# Subdomains most often left pointing at a decommissioned SaaS tenant.
_TAKEOVER_PROBE_LABELS = (
    "www",
    "mail",
    "blog",
    "docs",
    "status",
    "support",
    "shop",
    "cdn",
    "assets",
    "app",
    "portal",
    "dev",
    "staging",
    "test",
)

# Providers whose dangling CNAMEs are commonly claimable by anyone who
# registers the matching tenant name. Presence here raises severity; absence
# does not mean a dangling record is safe.
_TAKEOVER_PRONE_SUFFIXES = (
    "s3.amazonaws.com",
    "cloudfront.net",
    "github.io",
    "herokuapp.com",
    "herokudns.com",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "netlify.app",
    "netlify.com",
    "ghost.io",
    "wpengine.com",
    "pantheonsite.io",
    "zendesk.com",
    "freshdesk.com",
    "helpscoutdocs.com",
    "statuspage.io",
    "surge.sh",
    "bitbucket.io",
    "fastly.net",
    "readthedocs.io",
    "shopify.com",
    "myshopify.com",
    "webflow.io",
    "unbouncepages.com",
    "helpjuice.com",
    "tilda.ws",
    "launchrock.com",
)


def _error(check: str, domain: str, message: str) -> CheckResult:
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


@register("dnssec")
def check_dnssec(ctx: CheckContext) -> CheckResult:
    """Detect whether the zone is signed, via its DS record at the parent.

    The DS record is the authoritative signal that the parent zone has been
    told to expect signed answers. The AD flag is recorded too, but on its own
    it only tells you the *resolver* validated — a non-validating resolver
    never sets it even for a properly signed zone.
    """
    domain = ctx.name
    try:
        ds = ctx.resolver.query(domain, "DS")
    except DNSError as exc:
        return _error("dnssec", domain, str(exc))

    signed = bool(ds.records)
    observations: dict[str, object] = {
        "ds_records": len(ds.records),
        "signed": signed,
        "resolver_authenticated": ds.authenticated,
    }
    findings: list[Finding] = []

    if signed:
        try:
            dnskey = ctx.resolver.query(domain, "DNSKEY")
        except DNSError:
            dnskey = None
        if dnskey is not None:
            observations["dnskey_records"] = len(dnskey.records)
            if not dnskey.records:
                # DS at the parent with no DNSKEY in the zone breaks resolution
                # for every validating resolver — an outage, not a warning.
                findings.append(
                    Finding(
                        domain=domain,
                        check="dnssec",
                        kind=FindingKind.POSTURE,
                        severity=Severity.CRITICAL,
                        title="DNSSEC is broken: DS record present but no DNSKEY",
                        detail=(
                            "The parent zone publishes a DS record but the zone itself has no "
                            "DNSKEY. Validating resolvers will fail to resolve this domain at all."
                        ),
                        remediation="Publish the matching DNSKEY, or remove the DS record at the registrar.",
                        references=(RFC_DNSSEC,),
                    )
                )
    else:
        findings.append(
            Finding(
                domain=domain,
                check="dnssec",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title="DNSSEC is not enabled",
                detail=(
                    f"{domain} has no DS record at its parent zone, so DNS answers for it "
                    "cannot be cryptographically validated and remain forgeable by an "
                    "on-path or cache-poisoning attacker."
                ),
                remediation="Enable DNSSEC signing at your DNS provider and publish the DS record at your registrar.",
                references=(RFC_DNSSEC,),
            )
        )

    return CheckResult(check="dnssec", domain=domain, observations=observations, findings=findings)


@register("caa")
def check_caa(ctx: CheckContext) -> CheckResult:
    """Check for CAA records restricting which CAs may issue for the domain."""
    domain = ctx.name
    try:
        answer = ctx.resolver.query(domain, "CAA")
    except DNSError as exc:
        return _error("caa", domain, str(exc))

    records = tuple(sorted(answer.records))
    issuers = sorted({_caa_value(r) for r in records if " issue" in f" {r}"} - {""})
    has_iodef = any("iodef" in r.lower() for r in records)

    observations: dict[str, object] = {
        "records": list(records),
        "issuers": issuers,
        "iodef": has_iodef,
    }
    findings: list[Finding] = []

    if not records:
        findings.append(
            Finding(
                domain=domain,
                check="caa",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title="No CAA records",
                detail=(
                    f"{domain} does not restrict which certificate authorities may issue for it. "
                    "Any public CA will issue a certificate to anyone who passes its validation."
                ),
                remediation='Publish a CAA record, e.g. 0 issue "letsencrypt.org", listing only the CAs you use.',
                references=(RFC_CAA,),
            )
        )
    elif not has_iodef:
        findings.append(
            Finding(
                domain=domain,
                check="caa",
                kind=FindingKind.POSTURE,
                severity=Severity.INFO,
                title="CAA record has no iodef reporting address",
                detail="Without iodef you are not notified when a CA blocks an unauthorised issuance attempt.",
                remediation='Add 0 iodef "mailto:security@yourdomain" to the CAA record set.',
                evidence={"records": list(records)},
                references=(RFC_CAA,),
            )
        )

    return CheckResult(check="caa", domain=domain, observations=observations, findings=findings)


def _caa_value(record: str) -> str:
    parts = record.split(None, 2)
    if len(parts) < 3:
        return ""
    return parts[2].strip().strip('"').strip().lower()


@register("cname")
def check_cname(ctx: CheckContext) -> CheckResult:
    """Look for dangling CNAMEs that expose the domain to subdomain takeover.

    A CNAME pointing at a name that no longer exists is claimable: whoever
    registers that name at the provider serves content on your subdomain, with
    a valid certificate, from your origin. This is one of the highest-impact
    and least-noticed external exposures.

    The probe list is intentionally small. Full subdomain enumeration belongs
    in a dedicated tool; the point here is to catch the common cases cheaply on
    every scheduled run.
    """
    domain = ctx.name
    findings: list[Finding] = []
    cnames: dict[str, str] = {}
    dangling: list[str] = []

    candidates = [domain] + [f"{label}.{domain}" for label in _TAKEOVER_PROBE_LABELS]

    for candidate in candidates:
        try:
            answer = ctx.resolver.query(candidate, "CNAME")
        except DNSError:
            continue
        if not answer.exists or not answer.records:
            continue

        target = answer.records[0].rstrip(".").lower()
        cnames[candidate] = target

        try:
            resolvable = ctx.resolver.exists(target)
        except DNSError:
            continue

        if resolvable:
            continue

        dangling.append(candidate)
        prone = next((s for s in _TAKEOVER_PRONE_SUFFIXES if target.endswith(s)), None)
        findings.append(
            Finding(
                domain=domain,
                check="cname",
                kind=FindingKind.POSTURE,
                severity=Severity.CRITICAL if prone else Severity.HIGH,
                title=f"Dangling CNAME on {candidate}",
                detail=(
                    f"{candidate} is a CNAME to {target}, which does not resolve. "
                    + (
                        f"{target} is hosted on {prone}, where the underlying name can typically "
                        "be claimed by any account holder — an attacker who registers it serves "
                        f"content on {candidate} under your domain."
                        if prone
                        else "An attacker who gains control of the target name can serve content "
                        f"on {candidate} under your domain."
                    )
                ),
                remediation=f"Remove the {candidate} CNAME record, or re-claim {target} at the provider.",
                evidence={"name": candidate, "target": target, "provider": prone},
                references=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                ),
            )
        )

    observations: dict[str, object] = {
        "probed": candidates,
        "cnames": dict(sorted(cnames.items())),
        "dangling": sorted(dangling),
    }
    return CheckResult(check="cname", domain=domain, observations=observations, findings=findings)
