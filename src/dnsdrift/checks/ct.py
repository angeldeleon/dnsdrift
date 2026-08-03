"""Certificate Transparency monitoring via crt.sh.

Every publicly-trusted certificate is logged to CT. Watching those logs for
your own domains is one of the cheapest ways to detect shadow IT (a team
standing up a service nobody told security about) and the early stages of
impersonation infrastructure.

crt.sh is a free community service with no SLA. This check treats a failure as
informational — a scan must not fail because a third-party service is slow.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from ..httpclient import HTTPError, safe_request
from ..models import CheckResult, Finding, FindingKind, Severity
from ..validation import ValidationError
from .base import CheckContext, register

log = logging.getLogger(__name__)

CRT_SH_ENDPOINT = "https://crt.sh/"

# crt.sh returns every historical entry for a busy domain. Cap what we parse so
# a large response cannot blow up memory or the state file.
_MAX_ENTRIES = 500


@register("ct")
def check_ct(ctx: CheckContext) -> CheckResult:
    domain = ctx.name
    lookback = ctx.settings.ct_lookback_days

    # quote() with an empty safe set: the domain is already validated, but the
    # encoding is applied anyway so this stays correct if validation changes.
    url = f"{CRT_SH_ENDPOINT}?q={quote(domain, safe='')}&output=json&exclude=expired"

    try:
        response = safe_request(
            "GET",
            url,
            timeout=max(ctx.settings.timeout_seconds * 3, 15.0),
            user_agent=ctx.settings.user_agent,
        )
    except (HTTPError, ValidationError) as exc:
        return _unavailable(domain, str(exc))

    if response.status_code != 200:
        return _unavailable(domain, f"crt.sh returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        return _unavailable(domain, f"crt.sh returned a non-JSON response: {exc}")

    if not isinstance(payload, list):
        return _unavailable(domain, "crt.sh returned an unexpected payload shape")

    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback)
    entries = _parse_entries(payload[:_MAX_ENTRIES])
    recent = [e for e in entries if e["entry_timestamp"] and e["entry_timestamp"] >= cutoff.isoformat()]

    issuers = sorted({e["issuer"] for e in entries if e["issuer"]})
    all_names = sorted({name for e in entries for name in e["names"]})

    observations: dict[str, Any] = {
        "total_unexpired_certs": len(entries),
        "issuers": issuers,
        "covered_names": all_names[:200],
        "recent_count": len(recent),
        # Deliberately excluded from the diff surface: the full recent list
        # changes on every renewal and would make every run look like drift.
        # Newly-appearing *names* are what matter, and drift.py diffs those.
    }

    findings: list[Finding] = []
    if recent:
        findings.append(
            Finding(
                domain=domain,
                check="ct",
                kind=FindingKind.POSTURE,
                severity=Severity.INFO,
                title=f"{len(recent)} certificate(s) issued in the last {lookback} days",
                detail=(
                    "Newly logged certificates for this domain. Routine renewals look like this "
                    "too — the signal to act on is an issuer or hostname you do not recognise."
                ),
                remediation="Confirm each issuance was expected.",
                evidence={
                    "certificates": [
                        {
                            "issuer": e["issuer"],
                            "names": e["names"][:10],
                            "logged_at": e["entry_timestamp"],
                        }
                        for e in recent[:20]
                    ]
                },
                references=("https://certificate.transparency.dev/",),
            )
        )

    return CheckResult(check="ct", domain=domain, observations=observations, findings=findings)


def _parse_entries(payload: list[Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        raw_names = str(item.get("name_value") or "")
        names = sorted({n.strip().lower() for n in raw_names.splitlines() if n.strip()})
        entries.append(
            {
                "issuer": str(item.get("issuer_name") or "").strip()[:300],
                "names": names[:50],
                "entry_timestamp": _normalize_timestamp(item.get("entry_timestamp")),
                "not_after": _normalize_timestamp(item.get("not_after")),
            }
        )
    return entries


def _normalize_timestamp(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _unavailable(domain: str, message: str) -> CheckResult:
    log.info("CT check unavailable for %s: %s", domain, message)
    return CheckResult(
        check="ct",
        domain=domain,
        error=message,
        observations={},
        findings=[
            Finding(
                domain=domain,
                check="ct",
                kind=FindingKind.OPERATIONAL,
                severity=Severity.INFO,
                title="Certificate Transparency lookup unavailable",
                detail=f"Could not query crt.sh: {message}",
                remediation="No action needed; crt.sh is a best-effort third-party service.",
            )
        ],
    )
