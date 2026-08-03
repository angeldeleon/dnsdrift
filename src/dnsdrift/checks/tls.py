"""TLS certificate inspection.

Note on the unverified connection below: to *report* on a certificate that is
expired, self-signed, or has a hostname mismatch, the tool has to be able to
retrieve it — and a verifying connection refuses the handshake in exactly those
cases, which are the ones worth alerting on. So the inspection socket disables
verification deliberately, and compensates:

* it sends **no** application data — the handshake completes, the peer
  certificate is read, the socket closes;
* nothing retrieved over it is trusted, executed, or forwarded anywhere;
* validity is then evaluated in code, from the certificate itself, rather than
  being delegated to the handshake.

This is the standard pattern for a certificate scanner. It is confined to this
module; :mod:`dnsdrift.httpclient`, which carries actual data, always verifies.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..models import CheckResult, Finding, FindingKind, Severity
from ..validation import ValidationError, resolve_public_ips
from .base import CheckContext, register

# Signature algorithms that no longer provide collision resistance.
_WEAK_SIGNATURE_HASHES = {"md5", "sha1"}

_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 256


@register("tls")
def check_tls(ctx: CheckContext) -> CheckResult:
    domain = ctx.name
    host = ctx.domain.tls_host or domain
    findings: list[Finding] = []

    try:
        # Refuse to open a socket to a domain that resolves internally. Without
        # this, a config entry could aim the scanner at an internal service.
        resolve_public_ips(host, port=443)
    except ValidationError as exc:
        return CheckResult(
            check="tls",
            domain=domain,
            error=str(exc),
            observations={"host": host, "reachable": False},
            findings=[
                Finding(
                    domain=domain,
                    check="tls",
                    kind=FindingKind.OPERATIONAL,
                    severity=Severity.LOW,
                    title="TLS check skipped",
                    detail=str(exc),
                    remediation="Confirm the domain is publicly resolvable.",
                )
            ],
        )

    try:
        der, negotiated_protocol, negotiated_cipher = _fetch_peer_certificate(
            host, timeout=ctx.settings.timeout_seconds
        )
    except (OSError, ssl.SSLError) as exc:
        return CheckResult(
            check="tls",
            domain=domain,
            error=f"could not establish TLS connection to {host}:443: {exc}",
            observations={"host": host, "reachable": False},
            findings=[
                Finding(
                    domain=domain,
                    check="tls",
                    kind=FindingKind.OPERATIONAL,
                    severity=Severity.INFO,
                    title="No TLS service on port 443",
                    detail=f"Could not complete a TLS handshake with {host}:443 ({exc}).",
                    remediation="If this host is meant to serve HTTPS, investigate; otherwise ignore.",
                )
            ],
        )

    cert = x509.load_der_x509_certificate(der)

    not_after = _aware(
        cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    )
    not_before = _aware(
        cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before
    )
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    issuer = _common_name(cert.issuer) or cert.issuer.rfc4514_string()
    subject = _common_name(cert.subject) or cert.subject.rfc4514_string()
    sans = _subject_alt_names(cert)
    sig_hash = _signature_hash_name(cert)
    key_type, key_bits = _public_key_info(cert)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    observations: dict[str, object] = {
        "host": host,
        "reachable": True,
        "issuer": issuer,
        "subject": subject,
        "serial_number": format(cert.serial_number, "x"),
        "sha256_fingerprint": fingerprint,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_left,
        "subject_alt_names": sans,
        "signature_hash": sig_hash,
        "key_type": key_type,
        "key_bits": key_bits,
        "negotiated_protocol": negotiated_protocol,
        "negotiated_cipher": negotiated_cipher,
        "self_signed": cert.issuer == cert.subject,
    }

    if days_left < 0:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.CRITICAL,
                title=f"TLS certificate expired {abs(days_left)} days ago",
                detail=f"The certificate for {host} expired on {not_after.date().isoformat()}.",
                remediation="Renew and deploy the certificate immediately.",
                evidence={"not_after": not_after.isoformat(), "issuer": issuer},
            )
        )
    elif days_left <= ctx.settings.cert_expiry_critical_days:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"TLS certificate expires in {days_left} days",
                detail=f"The certificate for {host} expires on {not_after.date().isoformat()}.",
                remediation="Renew now; automated renewal has likely failed.",
                evidence={"not_after": not_after.isoformat(), "issuer": issuer},
            )
        )
    elif days_left <= ctx.settings.cert_expiry_warn_days:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.MEDIUM,
                title=f"TLS certificate expires in {days_left} days",
                detail=f"The certificate for {host} expires on {not_after.date().isoformat()}.",
                remediation="Confirm automated renewal is working.",
                evidence={"not_after": not_after.isoformat(), "issuer": issuer},
            )
        )

    if not_before > now:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="TLS certificate is not yet valid",
                detail=f"The certificate becomes valid on {not_before.date().isoformat()}.",
                remediation="Check the server clock and the deployed certificate.",
                evidence={"not_before": not_before.isoformat()},
            )
        )

    if not _hostname_matches(host, subject, sans):
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="TLS certificate does not cover this hostname",
                detail=(
                    f"{host} is not present in the certificate's subject alternative names "
                    f"({', '.join(sans) or 'none'}). Browsers will reject this connection."
                ),
                remediation=f"Reissue the certificate including {host} as a SAN.",
                evidence={"host": host, "subject_alt_names": sans},
            )
        )

    if observations["self_signed"]:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title="TLS certificate is self-signed",
                detail=f"The certificate for {host} is self-issued and not trusted by any client.",
                remediation="Replace with a certificate from a publicly trusted CA.",
                evidence={"issuer": issuer},
            )
        )

    if sig_hash in _WEAK_SIGNATURE_HASHES:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"TLS certificate uses a weak signature algorithm ({sig_hash})",
                detail=f"{sig_hash.upper()} is collision-vulnerable and rejected by modern clients.",
                remediation="Reissue the certificate with a SHA-256 or stronger signature.",
                evidence={"signature_hash": sig_hash},
            )
        )

    if key_type == "rsa" and key_bits < _MIN_RSA_BITS:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"TLS certificate uses a weak {key_bits}-bit RSA key",
                detail=f"RSA keys below {_MIN_RSA_BITS} bits no longer meet current guidance.",
                remediation=f"Reissue with an RSA key of at least {_MIN_RSA_BITS} bits, or an ECDSA P-256 key.",
                evidence={"key_type": key_type, "key_bits": key_bits},
            )
        )
    elif key_type == "ec" and key_bits < _MIN_EC_BITS:
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"TLS certificate uses a weak {key_bits}-bit EC key",
                detail=f"Elliptic-curve keys below {_MIN_EC_BITS} bits no longer meet current guidance.",
                remediation="Reissue with a P-256 or stronger curve.",
                evidence={"key_type": key_type, "key_bits": key_bits},
            )
        )

    if negotiated_protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(
            Finding(
                domain=domain,
                check="tls",
                kind=FindingKind.POSTURE,
                severity=Severity.HIGH,
                title=f"Server negotiated deprecated {negotiated_protocol}",
                detail=(
                    f"{host} accepted a {negotiated_protocol} handshake. TLS 1.0 and 1.1 are "
                    "deprecated by RFC 8996 and disabled in current browsers."
                ),
                remediation="Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                evidence={"protocol": negotiated_protocol},
                references=("https://www.rfc-editor.org/rfc/rfc8996",),
            )
        )

    return CheckResult(check="tls", domain=domain, observations=observations, findings=findings)


def _fetch_peer_certificate(host: str, *, timeout: float) -> tuple[bytes, str, str]:
    """Complete a handshake with *host* and return its certificate.

    Verification is disabled on purpose (see the module docstring): an expired
    or mismatched certificate is precisely what this check reports on, and a
    verifying context would refuse to hand it over. No application data is sent
    on this socket and nothing read from it is trusted.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Verification is off by design (see module docstring): an expired or
    # mismatched certificate is exactly what this check exists to report, and a
    # verifying context would abort before handing it over. Validity is then
    # asserted in code below, from the certificate itself.
    context.check_hostname = False  # noqa: S501
    context.verify_mode = ssl.CERT_NONE  # noqa: S501
    # Allow old protocols so that a server still speaking TLS 1.0 can be
    # detected and reported rather than appearing as an unreachable host.
    context.minimum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers("DEFAULT:@SECLEVEL=1")

    with socket.create_connection((host, 443), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            protocol = tls.version() or "unknown"
            cipher = (tls.cipher() or ("unknown",))[0]

    if not der:
        raise ssl.SSLError("peer presented no certificate")
    return der, protocol, cipher


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    if not isinstance(san, x509.SubjectAlternativeName):  # pragma: no cover - defensive
        return []
    return sorted(n.lower() for n in san.get_values_for_type(x509.DNSName))


def _signature_hash_name(cert: x509.Certificate) -> str:
    algorithm = cert.signature_hash_algorithm
    return algorithm.name.lower() if algorithm else "unknown"


def _public_key_info(cert: x509.Certificate) -> tuple[str, int]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size
    return type(key).__name__.lower(), getattr(key, "key_size", 0)


def _hostname_matches(host: str, subject_cn: str | None, sans: list[str]) -> bool:
    """RFC 6125 hostname matching, limited to a single leftmost wildcard.

    Falls back to the subject CN only when the certificate has no SANs at all,
    matching how clients have behaved since CN-only certificates were
    deprecated.
    """
    names = list(sans) or ([subject_cn.lower()] if subject_cn else [])
    host = host.lower().rstrip(".")

    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if not host.endswith(suffix):
                continue
            # A wildcard matches exactly one label, so "*.example.com" covers
            # "a.example.com" but not "a.b.example.com".
            remainder = host[: -len(suffix)]
            if remainder and "." not in remainder:
                return True
    return False
