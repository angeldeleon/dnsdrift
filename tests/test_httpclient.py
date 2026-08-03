"""End-to-end tests for the guarded HTTP client.

These run against two throwaway loopback servers. The SSRF guard is patched out
for the duration — it would (correctly) refuse to talk to 127.0.0.1, and what is
under test here is everything *after* the guard: transfer encodings, the size
cap, redirect handling, and credential stripping.

This file exists because its absence hid a real bug. The client was rewritten to
stream responses, and the rewrite broke every gzipped response — which is nearly
all of them — while the unit tests, which only imported helper functions, stayed
green. Guard behaviour is covered separately in ``test_validation.py``.
"""

from __future__ import annotations

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import dnsdrift.httpclient as hc
from dnsdrift.httpclient import MAX_RESPONSE_BYTES, HTTPError, safe_request

RECEIVED: list[dict] = []


class _Handler(BaseHTTPRequestHandler):
    """Serves the transfer shapes a real endpoint might return."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # noqa: A002 - silence test output
        pass

    def _record(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        RECEIVED.append(
            {
                "path": self.path,
                "method": self.command,
                "port": self.server.server_address[1],
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", "replace"),
            }
        )

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._record()
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._record()
        self._dispatch()

    def _dispatch(self) -> None:
        path = self.path
        if path.startswith("/plain"):
            self._send(json.dumps({"ok": True}).encode())
        elif path.startswith("/gzip"):
            payload = gzip.compress(json.dumps({"ok": True, "encoding": "gzip"}).encode())
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-encoding", "gzip")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        elif path.startswith("/chunked"):
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            for piece in (b'{"ok"', b":true", b"}"):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif path.startswith("/huge"):
            # Chunked and oversized, with no content-length to warn us first.
            self.send_response(200)
            self.send_header("transfer-encoding", "chunked")
            self.end_headers()
            block = b"A" * 65536
            try:
                for _ in range((MAX_RESPONSE_BYTES // len(block)) + 8):
                    self.wfile.write(f"{len(block):x}\r\n".encode() + block + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client aborted, which is the point
        elif path.startswith("/redirect-cross"):
            self._redirect(302, f"http://127.0.0.1:{_OTHER_PORT}/plain")
        elif path.startswith("/redirect-307-cross"):
            self._redirect(307, f"http://127.0.0.1:{_OTHER_PORT}/plain")
        elif path.startswith("/redirect-same"):
            self._redirect(302, "/plain")
        elif path.startswith("/redirect-loop"):
            self._redirect(302, "/redirect-loop")
        else:
            self._send(b"{}", status=404)

    def _redirect(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("location", location)
        self.send_header("content-length", "0")
        self.end_headers()

    def _send(self, payload: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


_OTHER_PORT = 0


class _QuietServer(ThreadingHTTPServer):
    """Suppresses the broken-pipe traceback the size-cap test deliberately causes.

    Aborting mid-body is the behaviour under test; the stdlib server printing a
    traceback about it would look like a failure in CI output.
    """

    def handle_error(self, request, client_address) -> None:
        pass


def _start() -> ThreadingHTTPServer:
    server = _QuietServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(scope="module")
def servers():
    global _OTHER_PORT
    primary = _start()
    secondary = _start()
    _OTHER_PORT = secondary.server_address[1]
    yield primary, secondary
    primary.shutdown()
    secondary.shutdown()


@pytest.fixture(autouse=True)
def allow_loopback(monkeypatch):
    """Bypass the SSRF guard so the transport itself can be exercised.

    The guard is tested directly and thoroughly in test_validation.py; patching
    it here is what makes it possible to test the code path behind it at all.
    """
    monkeypatch.setattr(hc, "assert_public_http_url", lambda url, require_https=True: url)
    RECEIVED.clear()


def _url(server, path: str) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}{path}"


class TestTransferEncodings:
    def test_plain_response(self, servers) -> None:
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/plain"), allow_http=True)
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_gzip_response(self, servers) -> None:
        """The regression this file was written for.

        iter_bytes() decompresses, so carrying the original content-encoding
        onto the rebuilt response made httpx decode the plaintext a second time
        and fail on essentially every real server.
        """
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/gzip"), allow_http=True)
        assert response.status_code == 200
        assert response.json()["encoding"] == "gzip"

    def test_chunked_response(self, servers) -> None:
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/chunked"), allow_http=True)
        assert response.json() == {"ok": True}


class TestSizeCap:
    def test_oversized_chunked_body_is_aborted(self, servers) -> None:
        """A chunked response has no content-length to reject up front."""
        primary, _ = servers
        with pytest.raises(HTTPError, match="exceeds"):
            safe_request("GET", _url(primary, "/huge"), allow_http=True, timeout=30.0)


class TestRedirects:
    def test_same_origin_redirect_is_followed(self, servers) -> None:
        primary, _ = servers
        response = safe_request("GET", _url(primary, "/redirect-same"), allow_http=True)
        assert response.json() == {"ok": True}

    def test_redirect_loop_is_capped(self, servers) -> None:
        primary, _ = servers
        with pytest.raises(HTTPError, match="too many redirects"):
            safe_request("GET", _url(primary, "/redirect-loop"), allow_http=True)

    def test_credentials_are_dropped_across_origins(self, servers) -> None:
        primary, secondary = servers
        safe_request(
            "POST",
            _url(primary, "/redirect-cross"),
            headers={"x-api-key": "SECRET-KEY-VALUE"},
            json_body={"findings": "sensitive"},
            allow_http=True,
        )
        second_hop = [r for r in RECEIVED if r["port"] == secondary.server_address[1]]
        assert second_hop, "the redirect was not followed"
        assert "x-api-key" not in second_hop[0]["headers"]
        assert "sensitive" not in second_hop[0]["body"]

    def test_credentials_survive_a_same_origin_redirect(self, servers) -> None:
        primary, _ = servers
        safe_request(
            "GET",
            _url(primary, "/redirect-same"),
            headers={"x-api-key": "SECRET-KEY-VALUE"},
            allow_http=True,
        )
        final = [r for r in RECEIVED if r["path"] == "/plain"]
        assert final and final[0]["headers"].get("x-api-key") == "SECRET-KEY-VALUE"

    def test_post_downgrades_to_get_on_302(self, servers) -> None:
        primary, _ = servers
        safe_request("POST", _url(primary, "/redirect-same"), json_body={"a": 1}, allow_http=True)
        final = [r for r in RECEIVED if r["path"] == "/plain"]
        assert final and final[0]["method"] == "GET"
        assert final[0]["body"] == ""

    def test_307_does_not_replay_the_body_cross_origin(self, servers) -> None:
        """307 preserves the method, so the body must be dropped explicitly."""
        primary, secondary = servers
        safe_request(
            "POST",
            _url(primary, "/redirect-307-cross"),
            headers={"authorization": "Bearer SECRET"},
            json_body={"findings": "sensitive"},
            allow_http=True,
        )
        second_hop = [r for r in RECEIVED if r["port"] == secondary.server_address[1]]
        assert second_hop
        assert "sensitive" not in second_hop[0]["body"]
        assert "authorization" not in second_hop[0]["headers"]


class TestHeaderInjection:
    def test_newline_in_header_is_rejected(self, servers) -> None:
        from dnsdrift.validation import ValidationError

        primary, _ = servers
        with pytest.raises(ValidationError, match="newline"):
            safe_request(
                "GET",
                _url(primary, "/plain"),
                headers={"x-api-key": "a\r\nX-Injected: 1"},
                allow_http=True,
            )
