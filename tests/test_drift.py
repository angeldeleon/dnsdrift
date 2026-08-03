"""Drift-engine tests.

The behaviours worth locking down here are the ones that make the tool
trustworthy over time: a downgrade must be caught, an improvement must not be
alarming, and an unchanged domain must produce absolute silence. That last one
is what stops the alert channel from being muted.
"""

from __future__ import annotations

from dnsdrift.drift import diff_snapshots
from dnsdrift.models import FindingKind, Severity, Snapshot


def snap(domain: str = "example.com", **checks: dict) -> Snapshot:
    return Snapshot(domain=domain, collected_at="2026-01-01T00:00:00+00:00", checks=dict(checks))


class TestBaseline:
    def test_no_baseline_yields_no_drift(self) -> None:
        current = snap(dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}})
        assert diff_snapshots(None, current) == []

    def test_identical_snapshots_yield_nothing(self) -> None:
        observations = {
            "dmarc": {
                "record": "v=DMARC1; p=reject; rua=mailto:a@b.com",
                "tags": {"p": "reject", "rua": "mailto:a@b.com"},
                "pct": 100,
            },
            "spf": {"record": "v=spf1 -all", "all_qualifier": "-", "dns_lookups": 0},
            "mx": {"records": ["10 mx.example.com."]},
            "dnssec": {"signed": True},
            "caa": {"records": ['0 issue "letsencrypt.org"'], "issuers": ["letsencrypt.org"]},
            "cname": {"cnames": {}, "dangling": []},
            "tls": {
                "reachable": True,
                "issuer": "R3",
                "subject_alt_names": ["example.com"],
                "key_bits": 2048,
            },
        }
        assert diff_snapshots(snap(**observations), snap(**observations)) == []

    def test_check_absent_from_baseline_is_not_drift(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-"})
        current = snap(
            spf={"record": "v=spf1 -all", "all_qualifier": "-"},
            dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}},
        )
        assert diff_snapshots(previous, current) == []


class TestDMARCDrift:
    def test_policy_downgrade_to_none_is_critical(self) -> None:
        previous = snap(dmarc={"record": "v=DMARC1; p=reject", "tags": {"p": "reject"}})
        current = snap(dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}})

        findings = diff_snapshots(previous, current)
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].kind is FindingKind.DRIFT
        assert "downgraded" in findings[0].title

    def test_reject_to_quarantine_is_high(self) -> None:
        previous = snap(dmarc={"record": "x", "tags": {"p": "reject"}})
        current = snap(dmarc={"record": "x", "tags": {"p": "quarantine"}})
        findings = diff_snapshots(previous, current)
        assert [f.severity for f in findings] == [Severity.HIGH]

    def test_improvement_is_informational_not_alarming(self) -> None:
        previous = snap(dmarc={"record": "x", "tags": {"p": "none"}})
        current = snap(dmarc={"record": "x", "tags": {"p": "reject"}})
        findings = diff_snapshots(previous, current)
        assert [f.severity for f in findings] == [Severity.INFO]
        assert "strengthened" in findings[0].title

    def test_record_removal_is_critical(self) -> None:
        previous = snap(dmarc={"record": "v=DMARC1; p=reject", "tags": {"p": "reject"}})
        current = snap(dmarc={"record": None, "tags": {}})
        findings = diff_snapshots(previous, current)
        assert findings[0].severity is Severity.CRITICAL
        assert "removed" in findings[0].title

    def test_pct_reduction_is_flagged(self) -> None:
        previous = snap(dmarc={"record": "x", "tags": {"p": "reject"}, "pct": 100})
        current = snap(dmarc={"record": "x", "tags": {"p": "reject"}, "pct": 20})
        findings = diff_snapshots(previous, current)
        assert any("sampling rate reduced" in f.title for f in findings)

    def test_rua_redirect_is_flagged(self) -> None:
        previous = snap(dmarc={"record": "x", "tags": {"p": "reject", "rua": "mailto:us@ours.com"}})
        current = snap(dmarc={"record": "x", "tags": {"p": "reject", "rua": "mailto:them@evil.com"}})
        findings = diff_snapshots(previous, current)
        assert any("reporting address changed" in f.title for f in findings)


class TestSPFDrift:
    def test_qualifier_weakening_is_flagged(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "dns_lookups": 1})
        current = snap(spf={"record": "v=spf1 ~all", "all_qualifier": "~", "dns_lookups": 1})
        findings = diff_snapshots(previous, current)
        assert any(f.severity is Severity.HIGH and "weakened" in f.title for f in findings)

    def test_plus_all_is_critical(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "dns_lookups": 0})
        current = snap(spf={"record": "v=spf1 +all", "all_qualifier": "+", "dns_lookups": 0})
        findings = diff_snapshots(previous, current)
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_crossing_lookup_limit_is_flagged(self) -> None:
        previous = snap(spf={"record": "a", "all_qualifier": "-", "dns_lookups": 9})
        current = snap(spf={"record": "b", "all_qualifier": "-", "dns_lookups": 12})
        findings = diff_snapshots(previous, current)
        assert any("10 DNS-lookup limit" in f.title for f in findings)

    def test_removal_short_circuits_other_findings(self) -> None:
        previous = snap(spf={"record": "v=spf1 -all", "all_qualifier": "-", "dns_lookups": 0})
        current = snap(spf={"record": None, "records": [], "all_qualifier": None})
        findings = diff_snapshots(previous, current)
        assert len(findings) == 1
        assert "removed" in findings[0].title


class TestOtherDrift:
    def test_mx_change_is_high(self) -> None:
        previous = snap(mx={"records": ["10 mx1.example.com."]})
        current = snap(mx={"records": ["10 attacker.example.net."]})
        findings = diff_snapshots(previous, current)
        assert findings[0].severity is Severity.HIGH
        assert "MX records changed" in findings[0].title

    def test_dnssec_disabled_is_high(self) -> None:
        findings = diff_snapshots(snap(dnssec={"signed": True}), snap(dnssec={"signed": False}))
        assert findings[0].severity is Severity.HIGH

    def test_new_ca_authorised_is_flagged(self) -> None:
        previous = snap(caa={"records": ["a"], "issuers": ["letsencrypt.org"]})
        current = snap(caa={"records": ["a", "b"], "issuers": ["letsencrypt.org", "sketchy-ca.example"]})
        findings = diff_snapshots(previous, current)
        assert any("sketchy-ca.example" in f.title for f in findings)

    def test_newly_dangling_cname_is_critical(self) -> None:
        previous = snap(cname={"cnames": {"blog.example.com": "x.herokuapp.com"}, "dangling": []})
        current = snap(
            cname={"cnames": {"blog.example.com": "x.herokuapp.com"}, "dangling": ["blog.example.com"]}
        )
        findings = diff_snapshots(previous, current)
        assert findings[0].severity is Severity.CRITICAL

    def test_tls_issuer_change_is_flagged(self) -> None:
        previous = snap(tls={"reachable": True, "issuer": "R3", "subject_alt_names": ["example.com"]})
        current = snap(tls={"reachable": True, "issuer": "Sketchy CA", "subject_alt_names": ["example.com"]})
        findings = diff_snapshots(previous, current)
        assert any("issuer changed" in f.title for f in findings)

    def test_ct_new_hostname_is_flagged(self) -> None:
        previous = snap(ct={"covered_names": ["example.com", "www.example.com"]})
        current = snap(ct={"covered_names": ["example.com", "www.example.com", "vpn-sso.example.com"]})
        findings = diff_snapshots(previous, current)
        assert any("previously unseen" in f.title for f in findings)


class TestRobustness:
    def test_malformed_baseline_does_not_raise(self) -> None:
        previous = snap(dmarc={"tags": "not-a-dict"})
        current = snap(dmarc={"record": "v=DMARC1; p=none", "tags": {"p": "none"}})
        assert diff_snapshots(previous, current) == []

    def test_mismatched_domains_raise(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="different domains"):
            diff_snapshots(snap("a.example.com"), snap("b.example.com"))
