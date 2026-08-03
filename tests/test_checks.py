"""Check-logic tests against a fake resolver.

No network. A stub resolver returns canned answers so the parsing and severity
logic can be exercised deterministically, including the failure modes that
matter most — a resolver error must never be reported as "no record".
"""

from __future__ import annotations

import pytest

from dnsdrift.checks.base import CheckContext
from dnsdrift.checks.dns_hygiene import check_caa, check_cname, check_dnssec
from dnsdrift.checks.email_auth import check_dkim, check_dmarc, check_mx, check_spf
from dnsdrift.config import DomainConfig, Settings
from dnsdrift.models import FindingKind, Severity
from dnsdrift.resolver import DNSAnswer, DNSError, NameStatus


class FakeResolver:
    """Returns canned answers keyed by (name, rdtype)."""

    def __init__(self, answers: dict[tuple[str, str], object] | None = None) -> None:
        self.answers = answers or {}

    def _lookup(self, name: str, rdtype: str) -> DNSAnswer:
        value = self.answers.get((name, rdtype))
        if isinstance(value, Exception):
            raise value
        if value is None:
            return DNSAnswer(name=name, rdtype=rdtype, records=(), exists=True)
        return DNSAnswer(name=name, rdtype=rdtype, records=tuple(value))  # type: ignore[arg-type]

    def query(self, name: str, rdtype: str, *, validate_name: bool = False) -> DNSAnswer:
        return self._lookup(name, rdtype)

    def txt(self, name: str) -> DNSAnswer:
        return self._lookup(name, "TXT")

    def name_status(self, name: str) -> NameStatus:
        value = self.answers.get((name, "STATUS"), NameStatus.NXDOMAIN)
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]


def ctx(answers: dict, domain: str = "example.com", **kwargs) -> CheckContext:
    return CheckContext(
        domain=DomainConfig(name=domain, **kwargs),
        settings=Settings(),
        resolver=FakeResolver(answers),  # type: ignore[arg-type]
    )


def titles(result) -> list[str]:
    return [f.title for f in result.findings]


class TestSPF:
    def test_missing_record_is_high(self) -> None:
        result = check_spf(ctx({}))
        assert result.findings[0].severity is Severity.HIGH
        assert "No SPF record" in titles(result)

    def test_plus_all_is_critical(self) -> None:
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 +all"]}))
        assert any(f.severity is Severity.CRITICAL for f in result.findings)

    def test_hard_fail_record_is_clean(self) -> None:
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 ip4:198.51.100.0/24 -all"]}))
        assert result.findings == []
        assert result.observations["all_qualifier"] == "-"

    def test_multiple_records_flagged(self) -> None:
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 -all", "v=spf1 ~all"]}))
        assert "Multiple SPF records" in titles(result)

    def test_lookup_limit_exceeded(self) -> None:
        record = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(12)) + " -all"
        result = check_spf(ctx({("example.com", "TXT"): [record]}))
        assert any("exceeds the 10 DNS-lookup limit" in t for t in titles(result))

    def test_ptr_mechanism_flagged(self) -> None:
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 ptr -all"]}))
        assert any("deprecated ptr" in t for t in titles(result))

    def test_non_spf_txt_records_ignored(self) -> None:
        answers = {("example.com", "TXT"): ["google-site-verification=abc", "v=spf1 -all"]}
        result = check_spf(ctx(answers))
        assert result.observations["record_count"] == 1

    def test_resolver_error_is_operational_not_missing_record(self) -> None:
        """The regression that matters most: an outage must not read as a finding."""
        result = check_spf(ctx({("example.com", "TXT"): DNSError("timed out")}))
        assert result.error is not None
        assert result.findings[0].kind is FindingKind.OPERATIONAL
        assert "No SPF record" not in titles(result)


class TestDMARC:
    def test_missing_is_high(self) -> None:
        result = check_dmarc(ctx({}))
        assert result.findings[0].severity is Severity.HIGH

    def test_p_none_is_high(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:a@example.com"]}
        result = check_dmarc(ctx(answers))
        assert any(f.severity is Severity.HIGH and "p=none" in f.title for f in result.findings)

    def test_p_reject_with_rua_is_clean(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@example.com"]}
        result = check_dmarc(ctx(answers))
        assert result.findings == []
        assert result.observations["tags"]["p"] == "reject"

    def test_sp_none_undermines_parent(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com"]}
        result = check_dmarc(ctx(answers))
        assert any("Subdomain policy weakens the parent" in t for t in titles(result))

    def test_partial_pct_flagged(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=25; rua=mailto:a@b.com"]}
        result = check_dmarc(ctx(answers))
        assert any("only 25% of mail" in t for t in titles(result))

    def test_missing_rua_flagged(self) -> None:
        result = check_dmarc(ctx({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]}))
        assert any("aggregate report address" in t for t in titles(result))

    def test_tag_parsing_tolerates_whitespace(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1;  p = reject ;  rua = mailto:a@b.com "]}
        result = check_dmarc(ctx(answers))
        assert result.observations["tags"]["p"] == "reject"


class TestDKIM:
    def test_no_selectors_found_is_info_only(self) -> None:
        """Selectors cannot be enumerated, so absence must not be alarming."""
        result = check_dkim(ctx({}, dkim_selectors=("default", "google")))
        assert [f.severity for f in result.findings] == [Severity.INFO]

    def test_revoked_selector_flagged(self) -> None:
        answers = {("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p="]}
        result = check_dkim(ctx(answers, dkim_selectors=("default",)))
        assert any("revoked" in t for t in titles(result))
        assert result.observations["details"]["default"]["revoked"] is True

    def test_weak_key_flagged(self) -> None:
        answers = {("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=" + "A" * 100]}
        result = check_dkim(ctx(answers, dkim_selectors=("default",)))
        assert any("weak RSA key" in t for t in titles(result))

    def test_record_without_p_tag_is_handled(self) -> None:
        """A v=DKIM1 record with no p= tag at all must not crash the check."""
        answers = {("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa"]}
        result = check_dkim(ctx(answers, dkim_selectors=("default",)))
        assert result.findings, "expected a finding, not a silent pass"
        assert any("no p= tag" in t for t in titles(result))
        assert result.observations["details"]["default"]["key_length_b64"] == 0

    def test_strong_key_is_clean(self) -> None:
        answers = {("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=" + "A" * 400]}
        result = check_dkim(ctx(answers, dkim_selectors=("default",)))
        assert result.findings == []
        assert result.observations["selectors_found"] == ["default"]


class TestMX:
    def test_no_mx_is_info(self) -> None:
        result = check_mx(ctx({}))
        assert [f.severity for f in result.findings] == [Severity.INFO]

    def test_mx_present_is_clean(self) -> None:
        result = check_mx(ctx({("example.com", "MX"): ["10 mx.example.com."]}))
        assert result.findings == []
        assert result.observations["count"] == 1


class TestDNSSEC:
    def test_unsigned_is_low(self) -> None:
        result = check_dnssec(ctx({}))
        assert [f.severity for f in result.findings] == [Severity.LOW]

    def test_ds_without_dnskey_is_critical(self) -> None:
        answers = {("example.com", "DS"): ["12345 13 2 abcdef"], ("example.com", "DNSKEY"): []}
        result = check_dnssec(ctx(answers))
        assert any(f.severity is Severity.CRITICAL for f in result.findings)

    def test_properly_signed_is_clean(self) -> None:
        answers = {("example.com", "DS"): ["12345 13 2 abcdef"], ("example.com", "DNSKEY"): ["257 3 13 key"]}
        result = check_dnssec(ctx(answers))
        assert result.findings == []
        assert result.observations["signed"] is True


class TestCAA:
    def test_missing_is_low(self) -> None:
        result = check_caa(ctx({}))
        assert [f.severity for f in result.findings] == [Severity.LOW]

    def test_issuers_parsed(self) -> None:
        answers = {("example.com", "CAA"): ['0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.com"']}
        result = check_caa(ctx(answers))
        assert result.observations["issuers"] == ["letsencrypt.org"]
        assert result.observations["iodef"] is True
        assert result.findings == []


class TestHostnameMatching:
    """Wildcard matching must not over-match; that is a real bypass."""

    @pytest.mark.parametrize(
        ("host", "names", "expected"),
        [
            ("example.com", ["example.com"], True),
            ("www.example.com", ["*.example.com"], True),
            ("a.b.example.com", ["*.example.com"], False),
            ("example.com", ["*.example.com"], False),
            ("evil.com", ["example.com"], False),
            ("EXAMPLE.com", ["example.com"], True),
            ("example.com", [], False),
        ],
    )
    def test_matching(self, host: str, names: list[str], expected: bool) -> None:
        from dnsdrift.checks.tls import _hostname_matches

        assert _hostname_matches(host, None, names) is expected


class TestCNAMETakeover:
    """The dangling-CNAME check is the loudest thing this tool emits.

    A CRITICAL "your subdomain is claimable" alert that fires on a transient
    SERVFAIL at someone else's CDN would destroy trust in the whole tool, so
    each of these states gets an explicit test.
    """

    def _ctx(self, target: str, status):
        answers = {("www.example.com", "CNAME"): [target], (target, "STATUS"): status}
        return ctx(answers)

    def test_nxdomain_target_on_prone_provider_is_critical(self) -> None:
        result = check_cname(self._ctx("tenant.herokuapp.com", NameStatus.NXDOMAIN))
        assert any(f.severity is Severity.CRITICAL for f in result.findings)
        assert result.observations["dangling"] == ["www.example.com"]
        assert result.error is None

    def test_nxdomain_target_elsewhere_is_high(self) -> None:
        result = check_cname(self._ctx("gone.example.net", NameStatus.NXDOMAIN))
        assert [f.severity for f in result.findings] == [Severity.HIGH]

    def test_resolving_target_is_clean(self) -> None:
        result = check_cname(self._ctx("live.herokuapp.com", NameStatus.RESOLVES))
        assert result.findings == []
        assert result.observations["dangling"] == []

    def test_nodata_target_is_not_dangling(self) -> None:
        """A name with only MX/TXT records exists and cannot be claimed."""
        result = check_cname(self._ctx("mailonly.example.net", NameStatus.NODATA))
        assert result.observations["dangling"] == []
        assert not any(f.kind is FindingKind.POSTURE for f in result.findings)

    def test_lookup_failure_never_reports_takeover(self) -> None:
        """The regression that matters: a SERVFAIL is not an NXDOMAIN."""
        result = check_cname(self._ctx("cdn.example.net", DNSError("timed out")))
        assert result.observations["dangling"] == []
        assert not any(f.severity >= Severity.HIGH for f in result.findings)
        assert result.findings[0].kind is FindingKind.OPERATIONAL
        # The name is named as indeterminate so the drift engine can exclude it...
        assert result.observations["unresolved"] == ["www.example.com"]
        # ...but the observation is still recorded. Discarding it would mean a
        # domain with one flaky probe never builds a baseline, which would
        # silently disable takeover drift detection entirely.
        assert result.error is None


class TestCAAParsing:
    def test_issuewild_is_not_treated_as_issue(self) -> None:
        answers = {("example.com", "CAA"): ['0 issuewild "digicert.com"']}
        result = check_caa(ctx(answers))
        assert result.observations["issuers"] == []

    def test_parameters_are_stripped_from_the_issuer(self) -> None:
        answers = {("example.com", "CAA"): ['0 issue "letsencrypt.org; validationmethods=dns-01"']}
        result = check_caa(ctx(answers))
        assert result.observations["issuers"] == ["letsencrypt.org"]

    def test_semicolon_means_issuance_forbidden_not_a_ca_named_semicolon(self) -> None:
        result = check_caa(ctx({("example.com", "CAA"): ['0 issue ";"']}))
        assert result.observations["issuers"] == []
        assert result.observations["issuance_forbidden"] is True


class TestTruncationSafety:
    """A truncated RRset must never be persisted as if it were complete."""

    def test_truncated_txt_does_not_report_missing_spf(self) -> None:
        class TruncatingResolver(FakeResolver):
            def txt(self, name: str) -> DNSAnswer:
                return DNSAnswer(name=name, rdtype="TXT", records=("v=spf1 -all",), truncated=True)

        context = CheckContext(
            domain=DomainConfig(name="example.com"),
            settings=Settings(),
            resolver=TruncatingResolver(),  # type: ignore[arg-type]
        )
        result = check_spf(context)
        assert result.error is not None
        assert "No SPF record" not in titles(result)
        assert result.findings[0].kind is FindingKind.OPERATIONAL


class TestSPFEdgeCases:
    def test_redirect_is_a_valid_terminator(self) -> None:
        """v=spf1 redirect=... is common and must not be flagged."""
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 redirect=_spf.example.net"]}))
        assert "SPF record has no 'all' mechanism" not in titles(result)
        assert result.observations["redirect"] is True

    def test_qualified_ptr_is_still_flagged(self) -> None:
        result = check_spf(ctx({("example.com", "TXT"): ["v=spf1 +ptr -all"]}))
        assert any("deprecated ptr" in t for t in titles(result))


class TestDMARCEdgeCases:
    def test_version_prefix_is_not_accepted(self) -> None:
        result = check_dmarc(ctx({("_dmarc.example.com", "TXT"): ["v=DMARC12345; p=reject"]}))
        assert result.observations["record_count"] == 0

    def test_out_of_range_pct_is_flagged_and_normalised(self) -> None:
        answers = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=150; rua=mailto:a@b.com"]}
        result = check_dmarc(ctx(answers))
        assert any("out of range" in t for t in titles(result))
        assert result.observations["pct"] == 100

    def test_invalid_record_is_not_worse_than_no_record(self) -> None:
        no_record = check_dmarc(ctx({}))
        no_policy = check_dmarc(ctx({("_dmarc.example.com", "TXT"): ["v=DMARC1; rua=mailto:a@b.com"]}))
        assert max(f.severity for f in no_policy.findings) <= max(f.severity for f in no_record.findings)


class TestDKIMReliability:
    def test_failed_lookups_are_named_not_assumed_absent(self) -> None:
        """One timeout among many selectors must not read as 'selector removed'."""
        answers = {
            ("google._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=" + "A" * 400],
            ("selector1._domainkey.example.com", "TXT"): DNSError("timed out"),
        }
        result = check_dkim(ctx(answers, dkim_selectors=("google", "selector1")))
        assert result.observations["selectors_errored"] == ["selector1"]
        assert result.observations["selectors_found"] == ["google"]
        assert any(f.kind is FindingKind.OPERATIONAL for f in result.findings)
        # Recorded, not discarded: a domain with one persistently flaky selector
        # must still build a baseline for the other fifteen.
        assert result.error is None

    def test_key_type_tag_is_case_insensitive(self) -> None:
        answers = {("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=RSA; p=" + "A" * 100]}
        result = check_dkim(ctx(answers, dkim_selectors=("default",)))
        assert any("weak RSA key" in t for t in titles(result))
