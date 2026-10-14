"""Tests for the allowlist proxy."""

import contextlib
import http.client
import http.server
import json
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bulbi.errors import AuditLogError, SandboxError
from bulbi.proxy import (
    AllowAllPolicy,
    AllowlistPolicy,
    AuditAction,
    AuditLogReader,
    AuditLogWriter,
    ProxyServer,
    audit_log_path,
    policy_for,
)
from bulbi.proxy.handler import host_without_port
from bulbi.spec import NetworkSpec


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / ".bulbi" / "proxy.log"


@pytest.fixture
def proxy(log_path: Path) -> ProxyServer:
    p = ProxyServer(AllowlistPolicy(["httpbin.org", "example.com"]), AuditLogWriter(log_path))
    yield p
    p.stop()


def test_proxy_starts_and_stops(proxy: ProxyServer):
    port = proxy.start()
    assert port > 0
    proxy.stop()


def test_proxy_denies_unlisted_domain(proxy: ProxyServer, log_path: Path):
    port = proxy.start()

    # Try to reach a domain not in the allowlist via HTTP
    req = urllib.request.Request("http://evil.example.com/")
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
    opener = urllib.request.build_opener(handler)

    with pytest.raises(urllib.error.HTTPError) as exc_info:
        opener.open(req, timeout=5)
    assert exc_info.value.code == 403

    # Check the log
    denied = [entry for entry in AuditLogReader(log_path).entries() if entry.denied]
    assert len(denied) >= 1
    assert denied[0].domain == "evil.example.com"
    assert denied[0].action == "deny"


def test_proxy_log_format(proxy: ProxyServer, log_path: Path):
    port = proxy.start()

    # Make a request that will be denied
    req = urllib.request.Request("http://blocked.test/foo")
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"})
    opener = urllib.request.build_opener(handler)

    with contextlib.suppress(urllib.error.HTTPError):
        opener.open(req, timeout=5)

    assert log_path.exists()
    lines = log_path.read_text().strip().splitlines()
    assert len(lines) >= 1

    entry = json.loads(lines[0])
    assert "timestamp" in entry
    assert "domain" in entry
    assert "action" in entry
    assert "method" in entry


# ---- Local upstream helpers (no external network) ---------------------------


class _HelloHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def upstream_port():
    server = http.server.HTTPServer(("127.0.0.1", 0), _HelloHandler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _get_via_proxy(proxy_port: int, upstream_port: int) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    conn.request("GET", f"http://127.0.0.1:{upstream_port}/x")
    response = conn.getresponse()
    return response.status, response.read()


def _start(policy, log_path: Path) -> ProxyServer:
    return ProxyServer(policy, AuditLogWriter(log_path))


def test_allowed_http_request_is_forwarded_and_audited(log_path: Path, upstream_port: int):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        assert _get_via_proxy(proxy.start(), upstream_port) == (200, b"hello")
    finally:
        proxy.stop()
    (entry,) = AuditLogReader(log_path).entries()
    assert (entry.domain, entry.action, entry.method) == ("127.0.0.1", "allow", "GET")


def test_connect_tunnel_relays_bytes(log_path: Path, upstream_port: int):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.start(), timeout=5)
        conn.set_tunnel("127.0.0.1", upstream_port)
        conn.request("GET", "/")
        assert conn.getresponse().read() == b"hello"
        conn.close()
    finally:
        proxy.stop()
    (entry,) = AuditLogReader(log_path).entries()
    assert (entry.action, entry.method) == ("allow", "CONNECT")


def test_connect_to_unlisted_domain_is_denied(log_path: Path, upstream_port: int):
    proxy = _start(AllowlistPolicy([]), log_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.start(), timeout=5)
        conn.set_tunnel("127.0.0.1", upstream_port)
        with pytest.raises(OSError, match="403"):
            conn.request("GET", "/")
    finally:
        proxy.stop()
    assert [e.action for e in AuditLogReader(log_path).entries()] == ["deny"]


def test_network_default_allow_lets_unlisted_domains_through(log_path: Path, upstream_port: int):
    """Bug (a): network.default = "allow" used to be ignored by the proxy."""
    policy = policy_for(NetworkSpec(default="allow", allow=[]))
    proxy = _start(policy, log_path)
    try:
        assert _get_via_proxy(proxy.start(), upstream_port)[0] == 200
    finally:
        proxy.stop()


def test_proxy_cannot_start_twice(proxy: ProxyServer):
    proxy.start()
    with pytest.raises(SandboxError, match="already running"):
        proxy.start()


# ---- Policies ---------------------------------------------------------------


def test_allowlist_policy_is_exact_match():
    policy = AllowlistPolicy(["example.com"])
    assert policy.allows("example.com")
    assert not policy.allows("sub.example.com")
    assert not policy.allows("example.com.evil")


def test_allow_all_policy():
    assert AllowAllPolicy().allows("anything.test")


def test_policy_for_network_spec():
    assert isinstance(policy_for(NetworkSpec(default="deny")), AllowlistPolicy)
    assert isinstance(policy_for(NetworkSpec(default="allow")), AllowAllPolicy)


@pytest.mark.parametrize(
    ("host", "domain"),
    [
        ("example.com:443", "example.com"),
        ("example.com", "example.com"),
        ("[::1]:443", "::1"),
        ("[::1", "[::1"),
    ],
)
def test_host_without_port(host: str, domain: str):
    assert host_without_port(host) == domain


# ---- Audit log --------------------------------------------------------------


def test_audit_log_round_trip_with_injected_clock(log_path: Path):
    clock = lambda: datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)  # noqa: E731
    writer = AuditLogWriter(log_path, clock=clock)
    writer.record("a.com", AuditAction.ALLOW, "GET", "http://a.com/")
    writer.record("b.com", AuditAction.DENY, "CONNECT", "b.com:443")

    assert json.loads(log_path.read_text().splitlines()[0]) == {
        "timestamp": "2026-01-02T03:04:05+00:00",
        "domain": "a.com",
        "action": "allow",
        "method": "GET",
        "url": "http://a.com/",
    }
    reader = AuditLogReader(log_path)
    assert [e.domain for e in reader.entries()] == ["a.com", "b.com"]
    assert [e.domain for e in reader.entries() if e.denied] == ["b.com"]


def test_audit_reader_missing_log_is_empty(tmp_path: Path):
    reader = AuditLogReader(tmp_path / "nope.log")
    assert not reader.exists()
    assert reader.entries() == []


def test_audit_reader_rejects_malformed_lines(log_path: Path):
    log_path.parent.mkdir(parents=True)
    log_path.write_text('{"action": "deny"}\n\nnot json\n')
    with pytest.raises(AuditLogError, match="line 3"):
        AuditLogReader(log_path).entries()


def test_audit_log_path():
    assert audit_log_path(Path("/p")) == Path("/p/.bulbi/proxy.log")


# ---- B2: the policy decides on the host actually contacted ---------------------


def _raw_request(proxy_port: int, request_line: str, host: str) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    method, url = request_line.split(maxsplit=1)
    conn.putrequest(method, url, skip_host=True)
    conn.putheader("Host", host)
    conn.endheaders()
    return conn.getresponse().status


def test_host_header_spoof_is_denied_and_logged_with_real_target(
    log_path: Path, upstream_port: int
):
    proxy = _start(AllowlistPolicy(["allowed.test"]), log_path)
    try:
        status = _raw_request(
            proxy.start(), f"GET http://127.0.0.1:{upstream_port}/", "allowed.test"
        )
    finally:
        proxy.stop()
    assert status == 403
    (entry,) = AuditLogReader(log_path).entries()
    assert (entry.domain, entry.action) == ("127.0.0.1", "deny")


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "ftp://allowed.test/x", "https://allowed.test/", "/relative"]
)
def test_non_http_or_relative_targets_are_denied(log_path: Path, url: str):
    proxy = _start(AllowlistPolicy(["allowed.test"]), log_path)
    try:
        status = _raw_request(proxy.start(), f"GET {url}", "allowed.test")
    finally:
        proxy.stop()
    assert status == 403
    assert [e.action for e in AuditLogReader(log_path).entries()] == ["deny"]


def test_matching_host_header_is_allowed(log_path: Path, upstream_port: int):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        status = _raw_request(
            proxy.start(), f"GET http://127.0.0.1:{upstream_port}/", f"127.0.0.1:{upstream_port}"
        )
    finally:
        proxy.stop()
    assert status == 200


class _RedirectingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/missing":
            self.send_error(404, "nope")
            return
        self.send_response(302)
        self.send_header("Location", "http://unlisted.test/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def redirecting_port():
    server = http.server.HTTPServer(("127.0.0.1", 0), _RedirectingHandler)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def test_redirects_are_relayed_not_followed(log_path: Path, redirecting_port: int):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.start(), timeout=5)
        conn.request("GET", f"http://127.0.0.1:{redirecting_port}/")
        response = conn.getresponse()
    finally:
        proxy.stop()
    assert response.status == 302
    assert response.getheader("Location") == "http://unlisted.test/"
    assert [e.domain for e in AuditLogReader(log_path).entries()] == ["127.0.0.1"]


def test_upstream_error_status_is_relayed(log_path: Path, redirecting_port: int):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.start(), timeout=5)
        conn.request("GET", f"http://127.0.0.1:{redirecting_port}/missing")
        assert conn.getresponse().status == 404
    finally:
        proxy.stop()


def test_unreachable_upstream_is_a_502(log_path: Path):
    proxy = _start(AllowlistPolicy(["127.0.0.1"]), log_path)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.start(), timeout=5)
        conn.request("GET", "http://127.0.0.1:1/")
        assert conn.getresponse().status == 502
    finally:
        proxy.stop()


def test_allowlist_matching_ignores_case():
    assert AllowlistPolicy(["Example.COM"]).allows("example.com")
