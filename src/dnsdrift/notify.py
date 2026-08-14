"""Outbound notifications.

Webhook URLs are read from environment variables named in the config, never
from the config file itself, so a repository can carry a committed config
without carrying a secret. Every destination URL goes through the SSRF guard in
:mod:`dnsdrift.httpclient`, and no URL is ever written to a log or a report.
"""

from __future__ import annotations

import logging
import re

from .config import NotifyConfig
from .httpclient import HTTPError, safe_request
from .models import FindingKind, ScanReport, Severity
from .validation import ValidationError

log = logging.getLogger(__name__)

# Slack rejects oversized payloads and truncates long messages awkwardly.
_MAX_SLACK_FINDINGS = 20

# The generic webhook was the one destination with no cap: it serialised every
# finding at or above the threshold, evidence included, so a scan of a few
# hundred domains produced a request the receiver dropped — and the scan that
# found the most became the one that alerted least. The severity counts and the
# total stay whole, so a receiver can always tell it is looking at a subset and
# go to the report for the rest.
_MAX_WEBHOOK_FINDINGS = 100

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_SEVERITY_EMOJI = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":large_orange_diamond:",
    Severity.MEDIUM: ":warning:",
    Severity.LOW: ":information_source:",
    Severity.INFO: ":white_circle:",
}


def notify(report: ScanReport, config: NotifyConfig, *, user_agent: str = "dnsdrift") -> list[str]:
    """Send notifications for findings at or above the configured severity.

    Returns a list of human-readable error strings. Notification failures are
    reported but never raise: a scan that found a critical issue and could not
    reach Slack has still done its job, and its exit code must still reflect
    the finding rather than the delivery failure.
    """
    errors: list[str] = []

    relevant = [f for f in report.findings if f.severity >= config.min_severity]
    if not relevant:
        log.info("no findings at or above %s; skipping notifications", config.min_severity.value)
        return errors

    generic = config.webhook_url()
    if generic:
        try:
            _post_generic(generic, report, relevant, user_agent=user_agent)
        except (HTTPError, ValidationError) as exc:
            errors.append(f"webhook delivery failed: {exc}")
            log.error("webhook delivery failed: %s", exc)

    slack = config.slack_webhook_url()
    if slack:
        try:
            _post_slack(slack, report, relevant, user_agent=user_agent)
        except (HTTPError, ValidationError) as exc:
            errors.append(f"Slack delivery failed: {exc}")
            log.error("Slack delivery failed: %s", exc)

    return errors


def _post_generic(url: str, report: ScanReport, findings: list, *, user_agent: str) -> None:
    shown = findings[:_MAX_WEBHOOK_FINDINGS]
    payload = {
        "tool": "dnsdrift",
        "tool_version": report.tool_version,
        "scanned_at": report.finished_at,
        "domains_scanned": len(report.snapshots),
        "counts_by_severity": report.counts_by_severity(),
        "findings": [f.to_dict() for f in shown],
        "findings_total": len(findings),
        "findings_truncated": len(findings) > len(shown),
    }
    response = safe_request("POST", url, json_body=payload, user_agent=user_agent)
    if response.status_code >= 400:
        raise HTTPError(f"webhook returned HTTP {response.status_code}")


def _post_slack(url: str, report: ScanReport, findings: list, *, user_agent: str) -> None:
    counts = report.counts_by_severity()
    drift_count = sum(1 for f in findings if f.kind is FindingKind.DRIFT)

    header = f"*dnsdrift* — {len(findings)} finding(s) across {len(report.snapshots)} domain(s)" + (
        f", *{drift_count} changed since last scan*" if drift_count else ""
    )
    summary = (
        f"critical: {counts['critical']} · high: {counts['high']} · "
        f"medium: {counts['medium']} · low: {counts['low']}"
    )

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": summary}]},
        {"type": "divider"},
    ]

    for finding in findings[:_MAX_SLACK_FINDINGS]:
        emoji = _SEVERITY_EMOJI[finding.severity]
        marker = " _(changed)_" if finding.kind is FindingKind.DRIFT else ""
        # Two blocks, deliberately. The first is ours: the severity emoji, the
        # domain and the check name, all in positions we control. The domain
        # goes in a code span rather than bold — it is validated, but the check
        # name sits beside it and the pair reads as one field, and nothing
        # formats inside a code span.
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} `{_escape_code(finding.domain)}` · `{_escape_code(finding.check)}`{marker}"
                    ),
                },
            }
        )
        # The second carries the title and detail, which interpolate DNS record
        # contents and certificate subjects — attacker-chosen for any domain you
        # do not control — and it is plain_text with emoji disabled. Slack
        # applies no mrkdwn inside plain_text, so a certificate subject cannot
        # bold itself, open a code span, or expand `:white_check_mark:` into a
        # reassuring green tick above the finding it is attached to. Escaping
        # alone could not achieve that: Slack mrkdwn has no backslash escape, so
        # the only options are to mangle the value with lookalike characters or
        # to choose a context where the markup is not interpreted. This is the
        # latter.
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "emoji": False,
                    "text": f"{_plain(finding.title)}\n{_plain(_truncate(finding.detail, 400))}",
                },
            }
        )

    if len(findings) > _MAX_SLACK_FINDINGS:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_…and {len(findings) - _MAX_SLACK_FINDINGS} more. See the full report._",
                    }
                ],
            }
        )

    response = safe_request(
        "POST",
        url,
        json_body={"text": f"dnsdrift: {len(findings)} finding(s)", "blocks": blocks},
        user_agent=user_agent,
    )
    if response.status_code >= 400:
        raise HTTPError(f"Slack returned HTTP {response.status_code}")


def _escape(text: str) -> str:
    """Neutralise attacker-influenced text before it reaches a Slack channel.

    Domain names, DNS record contents and certificate subjects are all
    attacker-chosen for any domain you do not control. Escaping the mrkdwn
    entities is not sufficient on its own: a newline lets a crafted value forge
    an extra line in the alert (a fake ":white_circle: all checks passed", say),
    so control characters are collapsed to spaces first.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plain(text: str) -> str:
    """Prepare attacker-influenced text for a Slack ``plain_text`` field.

    No mrkdwn is interpreted there, so nothing needs escaping for formatting —
    and entity-escaping would be wrong, printing a literal ``&lt;`` into the
    channel. Control characters still have to go, because a newline would let a
    crafted record forge an extra line inside the block.
    """
    return " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())


def _escape_code(text: str) -> str:
    """Neutralise a value rendered inside a Slack code span.

    :func:`_escape` alone is not sufficient: a backtick in the value closes the
    span early and lets the remainder render as mrkdwn.
    """
    return _escape(text).replace("`", "'")


def _truncate(text: str, limit: int) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
