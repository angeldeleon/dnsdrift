"""Guarded HTTP client for the few outbound requests this tool makes.

Every request goes through :func:`safe_request`, which:

* validates the URL and confirms the host resolves to public address space
  before connecting (see :mod:`dnsdrift.validation`);
* re-validates after each redirect, because an allowed public URL redirecting
  to ``http://169.254.169.254/`` is the standard SSRF bypass;
* **drops credential-bearing headers and the request body when a redirect
  crosses origins**, so a 302 from an API host cannot forward your API key or
  your findings to a third party;
* streams the response and aborts once the size cap is exceeded, rather than
  buffering an unbounded body first;
* enforces certificate verification, a request timeout, and a redirect cap;
* redacts URLs in every error message, because for a webhook the path *is* the
  credential.

There is no code path in ``dnsdrift`` that makes an unguarded HTTP request.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from .validation import ValidationError, assert_public_http_url

log = logging.getLogger(__name__)

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Headers that authenticate the request and must never survive a hop to a
# different origin. Compared lowercase.
_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "x-api-key", "proxy-authorization", "cookie", "api-key", "x-auth-token"}
)


class HTTPError(Exception):
    """A guarded request failed."""


def safe_request(
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    headers: Mapping[str, str] | None = None,
    json_body: Any | None = None,
    user_agent: str = "dnsdrift",
    allow_http: bool = False,
) -> httpx.Response:
    """Perform an SSRF-guarded HTTP request.

    Redirects are followed manually so each hop can be re-validated. Raises
    :class:`HTTPError` on transport failure and :class:`ValidationError` if any
    URL in the chain points at non-public address space.
    """
    current = assert_public_http_url(url, require_https=not allow_http)

    request_headers = {
        "User-Agent": user_agent,
        "Accept": "application/json, text/plain;q=0.8, */*;q=0.5",
    }
    if headers:
        for key, value in headers.items():
            # Header injection guard: a newline in a header value can split the
            # request. httpx blocks most of this, but failing loudly is better
            # than depending on a library's internals.
            if any(c in str(value) for c in "\r\n") or any(c in str(key) for c in "\r\n"):
                raise ValidationError(f"illegal newline in header {key!r}")
            request_headers[str(key)] = str(value)

    current_method = method.upper()
    current_headers = dict(request_headers)
    current_body = json_body

    try:
        with httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=True,  # never disable: this client talks to real endpoints
            trust_env=False,  # ignore ambient HTTP(S)_PROXY, which could redirect traffic
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            for hop in range(MAX_REDIRECTS + 1):
                request = client.build_request(
                    current_method,
                    current,
                    headers=current_headers,
                    json=current_body,
                )
                response = client.send(request, stream=True)

                try:
                    location = response.headers.get("location") if response.is_redirect else None
                    if location:
                        if hop >= MAX_REDIRECTS:
                            raise HTTPError(f"too many redirects (>{MAX_REDIRECTS}) for {_redact(url)}")

                        next_url = urljoin(current, location)
                        # Re-validate the redirect target. This is the check
                        # that stops open-redirect-to-metadata-service chains.
                        next_url = assert_public_http_url(next_url, require_https=not allow_http)

                        if _origin(next_url) != _origin(current):
                            # httpx strips Authorization on cross-host redirects
                            # when it follows them itself; following manually
                            # means we have to do it, and for the same reason.
                            current_headers = {
                                k: v
                                for k, v in current_headers.items()
                                if k.lower() not in _CREDENTIAL_HEADERS
                            }
                            # The body is as sensitive as the headers: it carries
                            # the findings payload for a webhook. A 307/308 would
                            # otherwise replay it verbatim at the new origin.
                            current_body = None
                            log.debug("dropping credentials and body across origin change")

                        if response.status_code in (301, 302, 303) and current_method != "GET":
                            # RFC 9110 §15.4: these turn a POST into a GET. Not
                            # downgrading would replay the findings payload at
                            # the redirect target.
                            current_method = "GET"
                            current_body = None

                        current = next_url
                        continue

                    content = _read_capped(response, current)
                finally:
                    response.close()

                # Rebuild as a non-streaming response so callers can use
                # .json() / .content normally.
                #
                # iter_bytes() already decompressed the body, so the original
                # Content-Encoding must be dropped: leaving it would make httpx
                # try to decode the plaintext a second time and fail on every
                # gzipped response — which is very nearly all of them.
                rebuilt_headers = httpx.Headers(response.headers)
                rebuilt_headers.pop("content-encoding", None)
                rebuilt_headers["content-length"] = str(len(content))
                return httpx.Response(
                    status_code=response.status_code,
                    headers=rebuilt_headers,
                    content=content,
                    request=request,
                )

            # Unreachable: every iteration of the loop above either returns or
            # raises. Kept as a typed fallback for the checker.
            raise HTTPError(f"redirect handling fell through for {_redact(url)}")  # pragma: no cover
    except httpx.HTTPError as exc:
        raise HTTPError(f"request to {_redact(url)} failed: {exc}") from exc


def _read_capped(response: httpx.Response, url: str) -> bytes:
    """Read the body, aborting as soon as the cap is exceeded.

    Checking ``Content-Length`` alone is not enough: a chunked response omits it
    entirely, and a non-streaming read would have buffered the whole body into
    memory before any check could run.
    """
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise HTTPError(f"response from {_redact(url)} declares more than {MAX_RESPONSE_BYTES} bytes")

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise HTTPError(f"response from {_redact(url)} exceeds {MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default_port = 443 if parts.scheme == "https" else 80
    try:
        port = parts.port or default_port
    except ValueError:  # pragma: no cover - validated upstream
        port = default_port
    return (parts.scheme, (parts.hostname or "").lower(), port)


def _redact(url: str) -> str:
    """Strip everything after the host so a webhook token never reaches a log.

    For most webhook providers the secret lives in the URL *path*, not a query
    string, so logging the full URL on an error would leak the credential into
    a CI job log.
    """
    try:
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            return "<redacted url>"
        return f"{parts.scheme}://{parts.hostname}/<redacted>"
    except Exception:  # pragma: no cover - defensive
        return "<redacted url>"
