"""Regression tests for the hardening pass.

Each test here corresponds to a specific defect found during review. They are
grouped separately from the feature tests so it stays obvious that removing one
re-opens a known hole.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from dnsdrift.drift import diff_snapshots
from dnsdrift.httpclient import _CREDENTIAL_HEADERS, _origin, _redact
from dnsdrift.logging_setup import RedactingFilter, redact
from dnsdrift.models import ScanReport, Severity, Snapshot
from dnsdrift.validation import ValidationError
from test_checks import ctx, titles

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW_DIR = _REPO_ROOT / ".github" / "workflows"


def snap(domain: str = "example.com", **checks: dict) -> Snapshot:
    return Snapshot(domain=domain, collected_at="2026-01-01T00:00:00+00:00", checks=dict(checks))


def _monitor_workflow() -> dict[str, Any]:
    return yaml.safe_load((_WORKFLOW_DIR / "monitor.yml").read_text(encoding="utf-8"))


def _scan_step() -> dict[str, Any]:
    steps = _monitor_workflow()["jobs"]["monitor"]["steps"]
    return next(step for step in steps if step.get("id") == "scan")


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
    def test_paragraphs_survive_but_bullets_are_defused(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("Para one.\n\nPara two:\n- bullet a\n- bullet b")
        # Line structure is what makes the summary readable, so it is kept...
        assert "\n\n" in rendered
        assert rendered.splitlines()[0] == "Para one."
        # ...but a line is never allowed to open a block of its own.
        assert "\n- bullet a" not in rendered
        assert "\\- bullet a" in rendered

    def test_control_characters_still_removed(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("line\x00one\n\n\n\n\nline two <img>")
        assert "\x00" not in rendered
        assert "&lt;img>" in rendered
        assert "\n\n\n" not in rendered


class TestWorkflowExitCodeHandling:
    """The monitor workflow has to survive its own scan exiting non-zero.

    Actions runs a `run:` block with `bash -e`. `set -uo pipefail` looks like it
    replaces that, but it only adds flags — errexit stays on. The step therefore
    died on exactly the two exit codes it existed to route, and everything after
    the scan (the SARIF render, the recorded exit code, the two failure steps)
    never happened.
    """

    def test_errexit_is_cleared_before_the_scan(self) -> None:
        script = _scan_step()["run"]
        assert "set +e" in script
        assert script.index("set +e") < script.index("dnsdrift scan")

    def test_exit_code_is_always_recorded(self) -> None:
        script = _scan_step()["run"]
        assert "rc=$?" in script
        assert 'echo "exit_code=$rc" >> "$GITHUB_OUTPUT"' in script
        # The step must succeed so the steps keyed on the recorded code can run.
        assert script.rstrip().endswith("exit 0")

    def test_both_exit_codes_are_still_routed_to_a_job_result(self) -> None:
        conditions = {
            step.get("if")
            for step in _monitor_workflow()["jobs"]["monitor"]["steps"]
            if isinstance(step.get("if"), str)
        }
        assert "steps.scan.outputs.exit_code == '1'" in conditions
        assert "steps.scan.outputs.exit_code == '2'" in conditions


class TestWorkflowRendersSarifFromTheSameScan:
    """A second `dnsdrift scan` would diff against the baseline the first saved.

    Its SARIF would carry every posture finding and no drift — which is the half
    of the output that justifies running the tool on a schedule at all.
    """

    def test_the_workflow_scans_exactly_once(self) -> None:
        script = _scan_step()["run"]
        assert script.count("dnsdrift scan") == 1

    def test_sarif_is_an_extra_rendering_of_that_scan(self) -> None:
        assert "--extra-output sarif:findings.sarif" in _scan_step()["run"]


class TestActionPinning:
    def test_every_action_is_pinned_to_a_commit_sha(self) -> None:
        import re

        for path in sorted(_WORKFLOW_DIR.glob("*.yml")):
            for match in re.finditer(r"uses:\s*(\S+)", path.read_text(encoding="utf-8")):
                ref = match.group(1).split("@", 1)
                assert len(ref) == 2, f"{path.name}: {match.group(1)} is unpinned"
                assert re.fullmatch(r"[0-9a-f]{40}", ref[1]), f"{path.name}: {match.group(1)} is not a SHA"

    def test_the_docs_do_not_still_claim_tag_pinning(self) -> None:
        """The claim outlived the fix, which is its own kind of defect."""
        for name in ("README.md", "SECURITY.md"):
            text = (_REPO_ROOT / name).read_text(encoding="utf-8").lower()
            assert "pinned to version tags" not in text
            assert "major version tags" not in text


class TestSingleScanRendersEveryFormat:
    def test_drift_reaches_the_sarif_rendering(self, tmp_path, monkeypatch) -> None:
        """The property the workflow depends on: one scan, every format, same findings."""
        import json

        from dnsdrift import cli
        from dnsdrift.models import Finding, FindingKind, ScanReport

        drift = Finding(
            domain="example.com",
            check="dmarc",
            kind=FindingKind.DRIFT,
            severity=Severity.CRITICAL,
            title="DMARC policy downgraded: p=reject -> p=none",
            detail="Enforcement was weakened.",
        )
        report = ScanReport(
            started_at="t",
            finished_at="t",
            tool_version="0",
            snapshots=[snap()],
            findings=[drift],
            baseline_available=True,
            checks_run=1,
        )
        monkeypatch.setattr(cli, "scan", lambda config, store=None: report)

        config = tmp_path / "domains.yml"
        config.write_text("domains:\n  - example.com\n", encoding="utf-8")
        markdown = tmp_path / "report.md"
        sarif = tmp_path / "findings.sarif"

        code = cli.main(
            [
                "scan",
                "-c",
                str(config),
                "--state",
                str(tmp_path / "state.json"),
                "-o",
                str(markdown),
                "--extra-output",
                f"sarif:{sarif}",
                "--no-notify",
            ]
        )

        assert code == cli.EXIT_FINDINGS
        assert "DMARC policy downgraded" in markdown.read_text(encoding="utf-8")
        results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
        assert [r["properties"]["kind"] for r in results] == ["drift"]

    def test_unknown_extra_format_is_rejected(self) -> None:
        from dnsdrift.cli import _parse_extra_outputs

        with pytest.raises(ValidationError, match="unknown format"):
            _parse_extra_outputs(["xml:findings.xml"])

    def test_extra_output_needs_both_halves(self) -> None:
        from dnsdrift.cli import _parse_extra_outputs

        for value in ("findings.sarif", "sarif:", ":findings.sarif"):
            with pytest.raises(ValidationError, match="FORMAT:PATH"):
                _parse_extra_outputs([value])

    def test_stdout_is_reserved_for_the_primary_output(self) -> None:
        from dnsdrift.cli import _parse_extra_outputs

        with pytest.raises(ValidationError, match="stdout"):
            _parse_extra_outputs(["sarif:-"])


class TestReportFilePermissions:
    """The JSON rendering embeds the whole snapshot, same as the state file."""

    def test_report_is_written_owner_only(self, tmp_path) -> None:
        import stat

        from dnsdrift.cli import _write_report
        from dnsdrift.models import ScanReport

        report = ScanReport(started_at="t", finished_at="t", tool_version="0")
        path = tmp_path / "report.json"
        _write_report(report, str(path), "json")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_permissive_file_from_a_previous_run_is_tightened(self, tmp_path) -> None:
        import stat

        from dnsdrift.cli import _write_report
        from dnsdrift.models import ScanReport

        path = tmp_path / "report.md"
        path.write_text("stale", encoding="utf-8")
        path.chmod(0o644)
        _write_report(ScanReport(started_at="t", finished_at="t", tool_version="0"), str(path), "markdown")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestMarkdownLinkEscaping:
    """A certificate issuer is chosen by whoever holds the host being scanned."""

    def test_link_syntax_is_neutralised(self) -> None:
        from dnsdrift.report import _md

        rendered = _md("Example CA [renew now](https://attacker.example) Root")
        assert "[renew now](" not in rendered
        assert "\\[renew now\\]" in rendered

    def test_a_hostile_issuer_cannot_place_a_link_in_the_report(self) -> None:
        from dnsdrift.models import Finding, FindingKind, ScanReport
        from dnsdrift.report import render_markdown

        finding = Finding(
            domain="example.com",
            check="tls",
            kind=FindingKind.DRIFT,
            severity=Severity.MEDIUM,
            title="TLS certificate issuer changed",
            detail="The certificate is now issued by [renew now](https://attacker.example).",
        )
        rendered = render_markdown(
            ScanReport(started_at="t", finished_at="t", tool_version="0", findings=[finding])
        )
        assert "\\[renew now\\]" in rendered
        # No bracket the tool did not write itself survives unescaped, so the
        # link never forms however the payload is shaped.
        assert [i for i, c in enumerate(rendered) if c == "[" and rendered[i - 1] != "\\"] == []


class TestAISummaryCannotForgeSections:
    """The summariser reads DNS records it does not control.

    Its reply is prose nothing parses, but prose in a Markdown report can still
    *look* like structure, and a forged "## Changes since last scan (0)" above
    the real findings is the whole payoff for a prompt injection.
    """

    def test_a_forged_heading_is_neutralised(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("All fine.\n\n## Changes since last scan (0)\n\nNo findings.")
        assert "\n## " not in rendered
        assert "\\## Changes since last scan (0)" in rendered

    def test_forged_bullets_tables_and_rules_are_neutralised(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("- bullet\n| Critical |\n---\n1. numbered\n> quote")
        for line in rendered.splitlines():
            assert line.startswith(("\\", "&gt;", "1\\")), line

    def test_paragraph_breaks_still_survive(self) -> None:
        from dnsdrift.report import _md_block

        rendered = _md_block("Para one.\n\nPara two.")
        assert rendered == "Para one.\n\nPara two."


class TestSPFVersionTerminator:
    """RFC 7208 §4.5: "v=spf1" must be followed by a space or end of record."""

    def test_a_lookalike_txt_record_is_not_a_second_spf_record(self) -> None:
        from dnsdrift.checks.email_auth import check_spf

        result = check_spf(
            ctx({("example.com", "TXT"): ["v=spf1 include:a.example -all", "v=spf10000 not-spf"]})
        )
        assert result.observations["record_count"] == 1
        assert not any("Multiple SPF" in t for t in titles(result))

    def test_a_genuine_second_record_is_still_reported(self) -> None:
        from dnsdrift.checks.email_auth import check_spf

        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}))
        assert result.observations["record_count"] == 2
        assert any("Multiple SPF" in t for t in titles(result))


class TestTakeoverSuffixBoundary:
    def test_a_lookalike_provider_domain_is_not_escalated(self) -> None:
        from dnsdrift.checks.dns_hygiene import check_cname

        result = check_cname(ctx({("www.example.com", "CNAME"): ["notgithub.io"]}))
        assert [f.severity for f in result.findings] == [Severity.HIGH]

    def test_a_real_provider_subdomain_is_still_critical(self) -> None:
        from dnsdrift.checks.dns_hygiene import check_cname

        result = check_cname(ctx({("www.example.com", "CNAME"): ["tenant.github.io"]}))
        assert any(f.severity is Severity.CRITICAL for f in result.findings)


class TestDeprecatedProtocolReporting:
    def test_every_reported_protocol_can_actually_be_negotiated(self) -> None:
        """A branch for a version the socket never offers is coverage we do not have."""
        import ssl

        from dnsdrift.checks.tls import _DEPRECATED_PROTOCOLS, MINIMUM_PROTOCOL

        assert MINIMUM_PROTOCOL is ssl.TLSVersion.TLSv1
        assert "SSLv3" not in _DEPRECATED_PROTOCOLS
        assert set(_DEPRECATED_PROTOCOLS) == {"TLSv1", "TLSv1.1"}


class TestStateFileIsOpenedThroughADescriptor:
    """The state path is usually relative, so in CI it sits in the checked-out repo."""

    def test_a_symlinked_state_file_is_refused(self, tmp_path) -> None:
        from dnsdrift.store import SnapshotStore, StateError

        target = tmp_path / "target.json"
        target.write_text('{"version": 1, "snapshots": {}}', encoding="utf-8")
        link = tmp_path / "state.json"
        link.symlink_to(target)

        with pytest.raises(StateError, match="cannot open state file"):
            SnapshotStore(link).load()

    def test_a_fifo_state_file_fails_rather_than_hanging(self, tmp_path) -> None:
        """O_NONBLOCK is the difference between a failure and a hung cron job."""
        import os

        from dnsdrift.store import SnapshotStore, StateError

        path = tmp_path / "state.json"
        os.mkfifo(path)

        with pytest.raises(StateError, match="not a regular file"):
            SnapshotStore(path).load()

    def test_a_permissive_state_file_is_tightened(self, tmp_path) -> None:
        import stat as stat_module

        from dnsdrift.store import SnapshotStore

        path = tmp_path / "state.json"
        path.write_text('{"version": 1, "snapshots": {}}', encoding="utf-8")
        path.chmod(0o644)

        SnapshotStore(path).load()
        assert stat_module.S_IMODE(path.stat().st_mode) == 0o600

    def test_a_missing_state_file_is_still_just_a_first_run(self, tmp_path) -> None:
        from dnsdrift.store import SnapshotStore

        assert SnapshotStore(tmp_path / "absent.json").load() == {}

    def test_a_corrupt_state_file_still_degrades_rather_than_raising(self, tmp_path) -> None:
        from dnsdrift.store import SnapshotStore

        path = tmp_path / "state.json"
        path.write_text("{not json", encoding="utf-8")
        assert SnapshotStore(path).load() == {}


class TestReportPathIsNotFollowed:
    """A report is written into a shared artefact directory on a build agent."""

    def test_a_symlinked_output_path_is_refused(self, tmp_path) -> None:
        from dnsdrift.cli import _write_report
        from dnsdrift.models import ScanReport

        target = tmp_path / "victim.txt"
        target.write_text("original", encoding="utf-8")
        link = tmp_path / "report.md"
        link.symlink_to(target)

        with pytest.raises(ValidationError, match="cannot write report"):
            _write_report(
                ScanReport(started_at="t", finished_at="t", tool_version="0"), str(link), "markdown"
            )

        assert target.read_text(encoding="utf-8") == "original"

    def test_the_symlink_target_is_not_chmodded(self, tmp_path) -> None:
        """The chmod is the second half of the attack: it locks the owner out."""
        import stat as stat_module

        from dnsdrift.cli import _write_report
        from dnsdrift.models import ScanReport

        target = tmp_path / "victim.txt"
        target.write_text("original", encoding="utf-8")
        target.chmod(0o644)
        link = tmp_path / "report.md"
        link.symlink_to(target)

        with pytest.raises(ValidationError):
            _write_report(
                ScanReport(started_at="t", finished_at="t", tool_version="0"), str(link), "markdown"
            )

        assert stat_module.S_IMODE(target.stat().st_mode) == 0o644


class TestBareUrlQuarantine:
    """A TXT record or certificate subject needs no metacharacter to phish."""

    def test_a_bare_url_is_moved_into_a_code_span(self) -> None:
        from dnsdrift.report import _md

        rendered = _md("Verify your domain at https://attacker.example/dns")
        assert "`https://attacker.example/dns`" in rendered

    def test_a_www_url_is_quarantined_too(self) -> None:
        from dnsdrift.report import _md

        assert "`www.attacker.example/dns`" in _md("go to www.attacker.example/dns")

    def test_a_finding_detail_cannot_autolink(self) -> None:
        from dnsdrift.models import Finding, FindingKind, ScanReport
        from dnsdrift.report import render_markdown

        finding = Finding(
            domain="example.com",
            check="tls",
            kind=FindingKind.POSTURE,
            severity=Severity.MEDIUM,
            title="TLS certificate issuer changed",
            detail="Renew at https://attacker.example/renew immediately.",
        )
        rendered = render_markdown(
            ScanReport(started_at="t", finished_at="t", tool_version="0", findings=[finding])
        )
        assert "`https://attacker.example/renew`" in rendered

    def test_tool_authored_punctuation_is_not_escaped(self) -> None:
        """Over-escaping is its own failure: nobody trusts a report that cannot punctuate."""
        from dnsdrift.report import _md

        assert _md("SPF permits all senders (+all)") == "SPF permits all senders (+all)"
        assert _md("2 certificate(s) issued") == "2 certificate(s) issued"

    def test_a_backtick_cannot_open_a_span(self) -> None:
        from dnsdrift.report import _md

        assert _md("issuer ` inject") == "issuer \\` inject"


class TestEvidenceIsScrubbedAtSerialisation:
    """Evidence is built from records a domain publishes, and rendered four ways."""

    def test_a_credential_shaped_key_is_redacted(self) -> None:
        from dnsdrift.models import Finding, FindingKind
        from dnsdrift.validation import REDACTED

        finding = Finding(
            domain="example.com",
            check="spf",
            kind=FindingKind.POSTURE,
            severity=Severity.LOW,
            title="t",
            detail="d",
            evidence={"record": "v=spf1 -all", "api_key": "AKIAIOSFODNN7EXAMPLE"},
        )
        out = finding.to_dict()
        assert out["evidence"]["api_key"] == REDACTED
        assert out["evidence"]["record"] == "v=spf1 -all"
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(out)

    def test_a_huge_record_set_is_bounded(self) -> None:
        from dnsdrift.models import Finding, FindingKind

        finding = Finding(
            domain="example.com",
            check="spf",
            kind=FindingKind.POSTURE,
            severity=Severity.LOW,
            title="t",
            detail="d",
            evidence={"records": ["x" * 4096 for _ in range(100)]},
        )
        records = finding.to_dict()["evidence"]["records"]
        assert len(records) == 51
        assert records[-1].endswith("more")
        assert all(len(r) <= 400 for r in records[:50])


class TestSerialisedReportIsBounded:
    def test_findings_are_capped_and_the_total_stays_whole(self) -> None:
        from dnsdrift.models import MAX_SERIALISED_FINDINGS as cap
        from dnsdrift.models import Finding, FindingKind, ScanReport

        findings = [
            Finding(
                domain="example.com",
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title=f"t{i}",
                detail="d",
            )
            for i in range(cap + 5)
        ]
        out = ScanReport(started_at="t", finished_at="t", tool_version="0", findings=findings).to_dict()
        assert len(out["findings"]) == cap
        assert out["findings_total"] == cap + 5
        assert out["findings_truncated"] is True

    def test_markdown_rendering_is_capped(self) -> None:
        from dnsdrift.models import Finding, FindingKind, ScanReport
        from dnsdrift.report import MAX_RENDERED_FINDINGS as cap
        from dnsdrift.report import render_markdown

        findings = [
            Finding(
                domain="example.com",
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.LOW,
                title=f"finding number {i}",
                detail="d",
            )
            for i in range(cap + 3)
        ]
        rendered = render_markdown(
            ScanReport(started_at="t", finished_at="t", tool_version="0", findings=findings)
        )
        assert "3 further finding(s) were not rendered" in rendered
        assert f"finding number {cap + 2}" not in rendered


class TestNotificationPayloadsAreBounded:
    def test_the_generic_webhook_payload_is_capped(self, monkeypatch) -> None:
        from dnsdrift import notify as notify_module
        from dnsdrift.models import Finding, FindingKind, ScanReport

        captured: dict = {}

        class _Response:
            status_code = 200

        def fake_request(method, url, **kwargs):
            captured.update(kwargs["json_body"])
            return _Response()

        monkeypatch.setattr(notify_module, "safe_request", fake_request)

        findings = [
            Finding(
                domain="example.com",
                check="spf",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"t{i}",
                detail="d",
            )
            for i in range(notify_module._MAX_WEBHOOK_FINDINGS + 10)
        ]
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", findings=findings)
        notify_module._post_generic("https://hook.example/x", report, findings, user_agent="dnsdrift")

        assert len(captured["findings"]) == notify_module._MAX_WEBHOOK_FINDINGS
        assert captured["findings_total"] == notify_module._MAX_WEBHOOK_FINDINGS + 10
        assert captured["findings_truncated"] is True


class TestSlackRendersUntrustedTextWhereMarkupIsNotInterpreted:
    """Slack mrkdwn has no backslash escape, so escaping cannot be the control."""

    def test_the_title_and_detail_go_in_a_plain_text_block(self, monkeypatch) -> None:
        from dnsdrift import notify as notify_module
        from dnsdrift.models import Finding, FindingKind, ScanReport

        captured: dict = {}

        class _Response:
            status_code = 200

        def fake_request(method, url, **kwargs):
            captured.update(kwargs["json_body"])
            return _Response()

        monkeypatch.setattr(notify_module, "safe_request", fake_request)

        finding = Finding(
            domain="example.com",
            check="tls",
            kind=FindingKind.POSTURE,
            severity=Severity.HIGH,
            title="*RESOLVED* :white_check_mark: nothing to see",
            detail="issued by `evil` CA",
        )
        report = ScanReport(started_at="t", finished_at="t", tool_version="0", findings=[finding])
        notify_module._post_slack("https://hooks.example/x", report, [finding], user_agent="dnsdrift")

        body = [b for b in captured["blocks"] if b.get("text", {}).get("type") == "plain_text"]
        assert body, "the untrusted half of the message must not be mrkdwn"
        assert body[0]["text"]["emoji"] is False
        assert "*RESOLVED*" in body[0]["text"]["text"]

    def test_a_backtick_cannot_close_the_code_span_around_the_domain(self) -> None:
        from dnsdrift.notify import _escape_code

        assert "`" not in _escape_code("example.com` *now*")


class TestADevicePathIsStillWritable:
    """`-o /dev/null` is a reasonable thing to write in a pipeline that only
    wants the exit code. The 0600 is for a real file; chmod-ing a character
    device is either a permission error or, as root, a machine-wide change."""

    def test_writing_to_dev_null_neither_fails_nor_chmods_it(self) -> None:
        import stat as stat_module

        from dnsdrift.cli import _write_report
        from dnsdrift.models import ScanReport

        before = stat_module.S_IMODE(os.stat("/dev/null").st_mode)
        _write_report(ScanReport(started_at="t", finished_at="t", tool_version="0"), "/dev/null", "json")
        assert stat_module.S_IMODE(os.stat("/dev/null").st_mode) == before
