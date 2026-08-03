"""Input validation and outbound-request guards.

This module is the trust boundary. Every externally-influenced string — a
domain from a config file, a webhook URL from an environment variable, a
hostname pulled out of a DNS answer — passes through here before the tool acts
on it.

Two threats drive the design:

1. **Injection into resolvers / URLs.** Domain names are interpolated into DNS
   queries and into ``crt.sh`` query strings. They are validated against a
   strict grammar and IDNA-encoded, not merely escaped.

2. **SSRF.** ``dnsdrift`` makes outbound HTTP requests to user-supplied webhook
   URLs, and it is frequently run inside CI or on a bastion with access to
   internal networks and cloud metadata endpoints. A webhook URL of
   ``http://169.254.169.254/latest/meta-data/iam/security-credentials/`` must
   not be followed. :func:`assert_public_http_url` resolves the host and
   rejects any address outside the public unicast ranges, and the HTTP client
   re-checks after every redirect.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

__all__ = [
    "ValidationError",
    "normalize_domain",
    "is_valid_domain",
    "normalize_selector",
    "assert_public_http_url",
    "resolve_public_ips",
]


class ValidationError(ValueError):
    """Raised when untrusted input fails validation."""


# A single DNS label: 1-63 chars, alphanumeric plus internal hyphens.
# Underscores are permitted because service labels (_dmarc, _domainkey) are
# real and we build them ourselves; they are still bounded by this grammar.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")

_MAX_DOMAIN_LENGTH = 253

# Suffixes that only ever resolve locally or are reserved by RFC 6761/8375.
# Scanning them is always a configuration mistake and sometimes an attempt to
# aim the tool at an internal resolver.
_FORBIDDEN_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".home.arpa",
    ".onion",
    ".invalid",
    ".test",
    ".example",
)


def is_valid_domain(value: str) -> bool:
    """Return True if *value* is a syntactically valid, scannable domain."""
    try:
        normalize_domain(value)
    except ValidationError:
        return False
    return True


def normalize_domain(value: str) -> str:
    """Validate and canonicalise a domain name.

    Returns the lowercase, IDNA-encoded (A-label) form with any trailing dot
    stripped. Raises :class:`ValidationError` on anything that is not a plain,
    publicly-resolvable domain.
    """
    if not isinstance(value, str):
        raise ValidationError(f"domain must be a string, got {type(value).__name__}")

    candidate = value.strip().strip(".").lower()

    if not candidate:
        raise ValidationError("domain is empty")

    # Reject anything carrying a scheme, path, port, credentials or whitespace.
    # Callers should pass a bare domain; silently stripping these would mask a
    # misconfigured config file.
    for bad in ("/", "\\", ":", "@", "?", "#", " ", "\t", "\n", "\r", ",", ";", "|", "&", "'", '"'):
        if bad in candidate:
            raise ValidationError(f"domain {value!r} contains an illegal character {bad!r}")

    if candidate.startswith("*"):
        raise ValidationError(f"wildcard domains are not scannable: {value!r}")

    # An IP address is not a domain. Accepting one would let a config point the
    # TLS check straight at an internal host.
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValidationError(f"{value!r} is an IP address, not a domain")

    try:
        # IDNA encoding both normalises Unicode domains and rejects a large
        # class of homograph and malformed inputs.
        encoded = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"domain {value!r} is not valid IDNA: {exc}") from exc

    if len(encoded) > _MAX_DOMAIN_LENGTH:
        raise ValidationError(f"domain {value!r} exceeds {_MAX_DOMAIN_LENGTH} characters")

    labels = encoded.split(".")
    if len(labels) < 2:
        raise ValidationError(f"domain {value!r} must have at least two labels")

    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(f"domain {value!r} has an invalid label {label!r}")

    for suffix in _FORBIDDEN_SUFFIXES:
        if encoded.endswith(suffix):
            raise ValidationError(
                f"domain {value!r} uses reserved suffix {suffix!r} and is not publicly scannable"
            )

    return encoded


def normalize_selector(value: str) -> str:
    """Validate a DKIM selector.

    Selectors are concatenated into ``<selector>._domainkey.<domain>``, so they
    get the same label grammar as any other DNS label.
    """
    if not isinstance(value, str):
        raise ValidationError(f"DKIM selector must be a string, got {type(value).__name__}")
    candidate = value.strip().lower()
    if not _LABEL_RE.match(candidate):
        raise ValidationError(f"invalid DKIM selector {value!r}")
    return candidate


def _is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally-routable unicast addresses.

    ``is_global`` alone is not sufficient: it does not exclude multicast, and on
    older Python versions its IPv6 handling has had gaps around mapped and
    translated addresses. The explicit checks below are cheap insurance.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        # ::ffff:169.254.169.254 and 64:ff9b::/96 are IPv6 spellings of IPv4
        # addresses. Unwrap and re-check rather than trusting the v6 flags.
        mapped = ip.ipv4_mapped or getattr(ip, "sixtofour", None)
        if mapped is not None:
            return _is_public_address(mapped)
        if ip.is_site_local:
            return False

    return ip.is_global


def resolve_public_ips(host: str, *, port: int = 443) -> list[str]:
    """Resolve *host* and return its addresses, or raise if any is not public.

    Fails closed on a mixed result. A host that resolves to one public and one
    private address is a classic DNS-rebinding shape, and there is no safe way
    to "use the good one" — by the time the HTTP client connects it may pick
    the other.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"cannot resolve host {host!r}: {exc}") from exc

    # getaddrinfo's sockaddr is (host, port) for IPv4 and a 4-tuple for IPv6;
    # element 0 is the address string in both cases.
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise ValidationError(f"host {host!r} resolved to no addresses")

    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise ValidationError(f"host {host!r} resolved to unparseable address {address!r}") from exc
        if not _is_public_address(parsed):
            raise ValidationError(
                f"refusing to connect to {host!r}: resolves to non-public address {address}"
            )

    return addresses


def assert_public_http_url(url: str, *, require_https: bool = True) -> str:
    """Validate an outbound URL and confirm it points somewhere public.

    Raises :class:`ValidationError` unless *url* is a well-formed http(s) URL
    with no embedded credentials whose host resolves entirely to public
    addresses.

    This check is necessarily time-of-check/time-of-use: DNS can change between
    validation and connection. It raises the bar substantially against
    accidental and opportunistic SSRF without claiming to be airtight. Callers
    that need a hard guarantee should pin the resolved address at connect time.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("URL is empty")

    parts = urlsplit(url.strip())

    allowed_schemes = ("https",) if require_https else ("https", "http")
    if parts.scheme not in allowed_schemes:
        raise ValidationError(
            f"URL scheme {parts.scheme!r} is not allowed (expected one of: {', '.join(allowed_schemes)})"
        )

    if parts.username or parts.password:
        raise ValidationError("URLs with embedded credentials are not allowed")

    host = parts.hostname
    if not host:
        raise ValidationError("URL has no host")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"URL has an invalid port: {exc}") from exc

    effective_port = port or (443 if parts.scheme == "https" else 80)

    # A literal IP host skips DNS entirely, so check it directly.
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        resolve_public_ips(host, port=effective_port)
    else:
        if not _is_public_address(literal):
            raise ValidationError(f"refusing to connect to non-public address {host}")

    return url.strip()
