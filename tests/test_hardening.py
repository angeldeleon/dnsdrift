"""Regression tests for the hardening pass.

Each test here corresponds to a specific defect found during review. They are
grouped separately from the feature tests so it stays obvious that removing one
re-opens a known hole.
"""

from __future__ import annotations

import logging

import pytest

from dnsdrift.drift import diff_snapshots
from dnsdrift.httpclient import _CREDENTIAL_HEADERS, _origin, _redact
from dnsdrift.logging_setup import RedactingFilter, redact
from dnsdrift.models import ScanReport, Severity, Snapshot
from dnsdrift.validation import ValidationError


def snap(domain: str = "example.com", **checks: dict) -> Snapshot:
    return Snapshot(domain=domain, collected_at="2026-01-01T00:00:00+00:00", checks=dict(checks))


class TestWebhookUrlRedaction:
    """For most webhook providers the secret is the URL *path*, not a query string."""

    def test_path_secret_is_redacted(self) -> None:
        url = "https://alerts.example.com/hooks/9f3c1e7b-SECRET-TOKEN-VALUE"
        assert "SECRET" not in _redact(url)
        assert _redact(url) == "https://alerts.example.com/<redacted>"

    def test_log_filter_catches_path_style_webhooks(self) -> None:
        message = "delivery failed for https://alerts.example.com/hooks/9f3c1e7bSECRETTOKENVALUE"
        assert "SECRETTOKENVALUE" not in redact(message)

    def test_garbage_input_does_not_raise(self) -> None:
        assert _redact("not a url") == "<redacted url>"

    def test_tracebacks_are_redacted(self) -> None:
        """Exception text is formatted separately and bypasses getMessage()."""
        filt = RedactingFilter()
        try:
            raise RuntimeError("posting to https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXXXXXX")
        except RuntimeError:
            import sys

            record = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed", None, sys.exc_info())
        filt.filter(record)
        assert record.exc_text is not None
        assert "XXXXXXXXXXXXXXXX" not in record.exc_text


class TestRedirectOrigin:
    """Credential headers must not survive a hop to a different origin."""

    def test_origin_comparison(self) -> None:
        assert _origin("https://a.example.com/x") == _origin("https://a.example.com/y")
        assert _origin("https://a.example.com/x") != _origin("https://b.example.com/x")
        assert _origin("https://a.example.com/x") != _origin("http://a.example.com/x")

    def test_default_ports_are_normalised(self) -> None:
        assert _origin("https://a.example.com") == _origin("https://a.example.com:443")

    def test_api_key_header_is_in_the_strip_list(self) -> None:
        # ai.py sends the Anthropic key as x-api-key; if this drops out of the
        # set, a 302 would forward it to the redirect target.
        assert "x-api-key" in _CREDENTIAL_HEADERS
        assert "authorization" in _CREDENTIAL_HEADERS


class TestInternalResolverGuard:
    def test_internal_resolver_is_rejected_by_default(self) -> None:
        from dnsdrift.config import parse_config

        with pytest.raises(ValidationError, match="not a public address"):
            parse_config({"domains": ["example.com"], "settings": {"resolvers": ["169.254.169.254"]}})

    def test_internal_resolver_allowed_when_explicit(self) -> None:
        from dnsdrift.config import parse_config

        config = parse_config(
            {
                "domains": ["example.com"],
                "settings": {"resolvers": ["10.0.0.53"], "allow_internal_resolvers": True},
            }
        )
        assert config.settings.resolvers == ("10.0.0.53",)

    def test_public_resolver_is_fine(self) -> None:
        from dnsdrift.config import parse_config

        config = parse_config({"domains": ["example.com"], "settings": {"resolvers": ["1.1.1.1"]}})
        assert config.settings.resolvers == ("1.1.1.1",)


class TestDegradedScan:
    """A scan where nothing could be checked must not exit 0."""

    def test_all_checks_failed_is_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=9, checks_failed=9)
        assert report.scan_degraded is True

    def test_majority_failed_is_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=9, checks_failed=5)
        assert report.scan_degraded is True

    def test_minority_failed_is_not_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=9, checks_failed=2)
        assert report.scan_degraded is False

    def test_exit_code_is_error_not_ok(self) -> None:
        from dnsdrift.cli import EXIT_ERROR, _exit_code

        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=4, checks_failed=4)
        assert _exit_code(report, Severity.HIGH) == EXIT_ERROR


class TestDriftHardening:
    def test_dropping_all_entirely_is_a_weakening(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "record_count": 1})
        current = snap(spf={"record": "v=spf1 include:x.example", "all_qualifier": None, "record_count": 1})
        findings = diff_snapshots(previous, current)
        assert any("weakened" in f.title for f in findings)

    def test_redirect_records_do_not_report_a_phantom_weakening(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "record_count": 1})
        current = snap(
            spf={
                "record": "v=spf1 redirect=_spf.example.net",
                "all_qualifier": None,
                "redirect": True,
                "record_count": 1,
            }
        )
        findings = diff_snapshots(previous, current)
        assert not any("weakened" in f.title for f in findings)

    def test_second_spf_record_is_drift(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "record_count": 1})
        current = snap(spf={"record": None, "records": ["a", "b"], "all_qualifier": "-", "record_count": 2})
        findings = diff_snapshots(previous, current)
        assert any("record to 2" in f.title and f.severity is Severity.HIGH for f in findings)

    def test_dmarc_removal_does_not_also_report_rua_removal(self) -> None:
        previous = snap(dmarc={"record": "v=DMARC1; p=reject", "tags": {"p": "reject", "rua": "mailto:a@b"}})
        current = snap(dmarc={"record": None, "tags": {}})
        findings = diff_snapshots(previous, current)
        assert len(findings) == 1
        assert "record was removed" in findings[0].title

    def test_truncated_ct_window_is_not_diffed(self) -> None:
        previous = snap(ct={"covered_names": ["a.example.com"], "names_truncated": True})
        current = snap(ct={"covered_names": ["z.example.com"], "names_truncated": True})
        assert diff_snapshots(previous, current) == []

    def test_untruncated_ct_still_reports_new_names(self) -> None:
        previous = snap(ct={"covered_names": ["a.example.com"], "names_truncated": False})
        current = snap(ct={"covered_names": ["a.example.com", "vpn.example.com"], "names_truncated": False})
        findings = diff_snapshots(previous, current)
        assert any("previously unseen" in f.title for f in findings)

    def test_https_going_away_is_now_detected(self) -> None:
        """Previously unreachable TLS was stored as an error, so this never fired."""
        previous = snap(tls={"reachable": True, "issuer": "R3", "host": "example.com"})
        current = snap(tls={"reachable": False, "host": "example.com"})
        findings = diff_snapshots(previous, current)
        assert any("stopped responding" in f.title for f in findings)


class TestCertificateTextSanitisation:
    """Certificate fields are attacker-chosen; they must not forge report lines."""

    def test_control_characters_are_stripped(self) -> None:
        from dnsdrift.checks.tls import _safe_text

        payload = "ok.example.com\n\n:white_circle: *acme.com* - all checks passed"
        cleaned = _safe_text(payload)
        assert "\n" not in cleaned
        assert len(cleaned) <= 256

    def test_slack_escaping_collapses_newlines(self) -> None:
        from dnsdrift.notify import _escape

        assert "\n" not in _escape("a\nb")
        assert _escape("<script>") == "&lt;script&gt;"

    def test_markdown_escaping_neutralises_html(self) -> None:
        from dnsdrift.report import _md

        # `<` is escaped because it opens an HTML tag...
        assert _md("<img src=x>") == "&lt;img src=x>"
        # ...but a mid-string `>` is inert, and escaping it would mangle every
        # "p=reject -> p=none" title into "-&gt;".
        assert _md("p=reject -> p=none") == "p=reject -> p=none"
        # A leading `>` would start a blockquote, so that one is escaped.
        assert _md("> forged quote").startswith("&gt;")
        assert "\n" not in _md("line1\nline2")


class TestWildcardMatching:
    def test_public_suffix_wildcard_is_rejected(self) -> None:
        """A '*.com' certificate should never be treated as covering x.com."""
        from dnsdrift.checks.tls import _hostname_matches

        assert _hostname_matches("x.com", None, ["*.com"]) is False
        assert _hostname_matches("a.example.com", None, ["*.example.com"]) is True


class TestIndeterminateExclusions:
    """A lookup we could not complete is unknown — never 'removed'."""

    def test_errored_dkim_selector_is_not_reported_as_disappeared(self) -> None:
        previous = snap(dkim={"selectors_found": ["google", "s1"], "selectors_errored": []})
        current = snap(dkim={"selectors_found": ["google"], "selectors_errored": ["s1"]})
        assert diff_snapshots(previous, current) == []

    def test_genuinely_removed_selector_is_still_reported(self) -> None:
        previous = snap(dkim={"selectors_found": ["google", "s1"], "selectors_errored": []})
        current = snap(dkim={"selectors_found": ["google"], "selectors_errored": []})
        findings = diff_snapshots(previous, current)
        assert any("disappeared" in f.title for f in findings)

    def test_unresolved_cname_is_not_reported_as_newly_dangling(self) -> None:
        previous = snap(
            cname={"cnames": {"www.example.com": "x.herokuapp.com"}, "dangling": [], "unresolved": []}
        )
        current = snap(
            cname={
                "cnames": {"www.example.com": "x.herokuapp.com"},
                "dangling": ["www.example.com"],
                "unresolved": ["www.example.com"],
            }
        )
        assert diff_snapshots(previous, current) == []

    def test_genuine_new_dangling_cname_is_still_critical(self) -> None:
        previous = snap(
            cname={"cnames": {"www.example.com": "x.herokuapp.com"}, "dangling": [], "unresolved": []}
        )
        current = snap(
            cname={
                "cnames": {"www.example.com": "x.herokuapp.com"},
                "dangling": ["www.example.com"],
                "unresolved": [],
            }
        )
        findings = diff_snapshots(previous, current)
        assert any(f.severity is Severity.CRITICAL for f in findings)


class TestDegradedFloor:
    def test_nothing_attempted_is_not_degraded(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0")
        assert report.scan_degraded is False

    def test_single_check_failure_does_not_trip_the_whole_scan(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=1, checks_failed=1)
        assert report.scan_degraded is False

    def test_majority_of_a_real_scan_still_trips_it(self) -> None:
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", checks_run=9, checks_failed=6)
        assert report.scan_degraded is True


class TestAISummaryFormatting:
    def test_paragraphs_and_bullets_survive(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("Para one.\n\nPara two:\n- bullet a\n- bullet b")
        assert "\n\n" in rendered
        assert "- bullet a" in rendered

    def test_control_characters_still_removed(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("line\x00one\n\n\n\n\nline two <img>")
        assert "\x00" not in rendered
        assert "&lt;img>" in rendered
        assert "\n\n\n" not in rendered
