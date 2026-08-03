"""Guarded HTTP client for the few outbound requests this tool makes.

Every request goes through :func:`safe_request`, which:

* validates the URL and confirms the host resolves to public address space
  before connecting (see :mod:`dnsdrift.validation`);
* re-validates after each redirect, because an allowed public URL redirecting
  to ``http://169.254.169.254/`` is the standard SSRF bypass;
* enforces certificate verification, a request timeout, a redirect cap, and a
  response-size cap.

There is no code path in ``dnsdrift`` that makes an unguarded HTTP request.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import httpx

from .validation import ValidationError, assert_public_http_url

log = logging.getLogger(__name__)

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


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

    try:
        with httpx.Client(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=True,  # never disable: this client talks to real endpoints
            trust_env=False,  # ignore ambient HTTP(S)_PROXY, which could redirect traffic
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        ) as client:
            for hop in range(MAX_REDIRECTS + 1):
                response = client.request(
                    method.upper(),
                    current,
                    headers=request_headers,
                    json=json_body,
                )

                if response.is_redirect and response.headers.get("location"):
                    if hop >= MAX_REDIRECTS:
                        raise HTTPError(f"too many redirects (>{MAX_REDIRECTS}) for {url}")
                    next_url = str(response.next_request.url) if response.next_request else None
                    if not next_url:
                        break
                    # Re-validate the redirect target. This is the check that
                    # stops open-redirect-to-metadata-service chains.
                    current = assert_public_http_url(next_url, require_https=not allow_http)
                    log.debug("following redirect to %s", current)
                    continue

                content_length = response.headers.get("content-length")
                if content_length and content_length.isdigit() and int(content_length) > MAX_RESPONSE_BYTES:
                    raise HTTPError(f"response from {current} exceeds {MAX_RESPONSE_BYTES} bytes")
                if len(response.content) > MAX_RESPONSE_BYTES:
                    raise HTTPError(f"response from {current} exceeds {MAX_RESPONSE_BYTES} bytes")

                return response

            raise HTTPError(f"redirect loop for {url}")
    except httpx.HTTPError as exc:
        raise HTTPError(f"request to {_redact(url)} failed: {exc}") from exc


def _redact(url: str) -> str:
    """Strip anything after the host so a webhook token never reaches a log."""
    try:
        scheme, _, rest = url.partition("://")
        host = rest.split("/", 1)[0]
        return f"{scheme}://{host}/<redacted>"
    except Exception:  # pragma: no cover - defensive
        return "<redacted url>"
