"""Tests for the trust boundary.

These are the most important tests in the repository. Everything else produces
a wrong answer when it breaks; this module produces an SSRF.
"""

from __future__ import annotations

import pytest

from dnsdrift.validation import (
    ValidationError,
    assert_public_http_url,
    is_valid_domain,
    normalize_domain,
    normalize_selector,
)


class TestNormalizeDomain:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Example.COM", "example.com"),
            ("example.com.", "example.com"),
            ("  example.com  ", "example.com"),
            ("sub.example.co.uk", "sub.example.co.uk"),
            ("xn--bcher-kva.com", "xn--bcher-kva.com"),
            ("bücher.example.com", "xn--bcher-kva.example.com"),
            ("_dmarc.example.com", "_dmarc.example.com"),
        ],
    )
    def test_accepts_and_canonicalises(self, raw: str, expected: str) -> None:
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "localhost",
            "example",  # single label
            "*.example.com",
            "example.com/path",
            "https://example.com",
            "example.com:8080",
            "user@example.com",
            "example.com\nevil.com",
            "example.com evil.com",
            "example.com;evil.com",
            "192.168.1.1",
            "127.0.0.1",
            "::1",
            "app.local",
            "db.internal",
            "thing.localhost",
            "secret.onion",
            "-leading.example.com",
            "trailing-.example.com",
            "a" * 64 + ".example.com",  # label too long
        ],
    )
    def test_rejects_dangerous_input(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            normalize_domain(raw)

    def test_rejects_overlong_domain(self) -> None:
        long_domain = ".".join(["abcdefghij"] * 30) + ".com"
        with pytest.raises(ValidationError, match="exceeds"):
            normalize_domain(long_domain)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError):
            normalize_domain(None)  # type: ignore[arg-type]

    def test_is_valid_domain_does_not_raise(self) -> None:
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("not a domain") is False


class TestNormalizeSelector:
    def test_accepts_valid(self) -> None:
        assert normalize_selector("Selector1") == "selector1"

    @pytest.mark.parametrize("raw", ["", "sel.ector", "sel ector", "a" * 64, "sel/ector", "-bad"])
    def test_rejects_invalid(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            normalize_selector(raw)


class TestSSRFGuard:
    """The URL guard must refuse anything that can reach internal services."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/",
            "http://localhost/",
            "https://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",  # carrier-grade NAT
            "http://0.0.0.0/",
            "http://[fd00::1]/",  # unique local
            "http://[fe80::1]/",  # link local
        ],
    )
    def test_rejects_internal_addresses(self, url: str) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url(url, require_https=False)

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/",
            "javascript:alert(1)",
            "data:text/plain,hello",
            "",
            "   ",
            "not a url",
        ],
    )
    def test_rejects_non_http_schemes(self, url: str) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url(url, require_https=False)

    def test_rejects_plain_http_by_default(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            assert_public_http_url("http://example.com/")

    def test_rejects_embedded_credentials(self) -> None:
        with pytest.raises(ValidationError, match="credentials"):
            assert_public_http_url("https://user:pass@example.com/")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(ValidationError):
            assert_public_http_url("https:///path")

    @pytest.mark.network
    def test_accepts_public_https_url(self) -> None:
        assert assert_public_http_url("https://example.com/webhook") == "https://example.com/webhook"
