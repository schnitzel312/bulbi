"""Per-request handling for the proxy: CONNECT tunnels and plain HTTP forwarding."""

from __future__ import annotations

import logging
import select
import socket
from http import HTTPStatus
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from bulbi.proxy.audit import AuditAction

if TYPE_CHECKING:
    from bulbi.proxy.server import ProxyContext, ProxyHTTPServer

logger = logging.getLogger(__name__)

TUNNEL_BUFFER_SIZE = 65536
UPSTREAM_TIMEOUT_SECONDS = 60
DEFAULT_TLS_PORT = 443
UNKNOWN_DOMAIN = "(unknown)"
DENIED_MESSAGE = "Domain not in allowlist"

# Headers that apply to a single connection and must not be forwarded.
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    }
)


def host_without_port(host: str) -> str:
    """Strip the port from ``host:port``; unwrap bracketed IPv6 addresses."""
    if host.startswith("["):
        bracket_end = host.find("]")
        return host[1:bracket_end] if bracket_end != -1 else host
    return host.rsplit(":", 1)[0] if ":" in host else host


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Applies the domain policy to each request, audits it, then forwards it."""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log; the audit log replaces it."""

    @property
    def _context(self) -> ProxyContext:
        return cast("ProxyHTTPServer", self.server).context

    def _admit(self, domain: str, method: str, url: str) -> bool:
        """Check the policy, audit the decision, and reply 403 if denied."""
        allowed = bool(domain) and self._context.policy.allows(domain)
        action = AuditAction.ALLOW if allowed else AuditAction.DENY
        self._context.audit.record(domain or UNKNOWN_DOMAIN, action, method, url)
        if not allowed:
            self.send_error(HTTPStatus.FORBIDDEN, DENIED_MESSAGE)
        return allowed

    # ---- CONNECT (HTTPS tunnelling) ---------------------------------------

    def do_CONNECT(self) -> None:
        if not self._admit(host_without_port(self.path), "CONNECT", self.path):
            return
        target = self._connect_target()
        if target is None:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid port")
            return
        try:
            upstream = socket.create_connection(target, timeout=UPSTREAM_TIMEOUT_SECONDS)
        except OSError as exc:
            logger.debug("CONNECT upstream failed for %s: %s", self.path, exc)
            self.send_error(HTTPStatus.BAD_GATEWAY, "Failed to connect to upstream")
            return
        self.send_response(HTTPStatus.OK, "Connection Established")
        self.end_headers()
        self._relay(self.connection, upstream)

    def _connect_target(self) -> tuple[str, int] | None:
        host, _, port = self.path.rpartition(":")
        if not host:
            return self.path, DEFAULT_TLS_PORT
        return (host, int(port)) if port.isdigit() else None

    @staticmethod
    def _relay(client: socket.socket, upstream: socket.socket) -> None:
        """Shuttle bytes both ways until either side closes, errors, or goes idle."""
        sockets = [client, upstream]
        try:
            for sock in sockets:
                sock.setblocking(False)
            while True:
                readable, _, failed = select.select(sockets, [], sockets, UPSTREAM_TIMEOUT_SECONDS)
                if failed or not readable:
                    return
                for sock in readable:
                    peer = upstream if sock is client else client
                    try:
                        data = sock.recv(TUNNEL_BUFFER_SIZE)
                        if not data:
                            return
                        peer.sendall(data)
                    except OSError:
                        return
        finally:
            upstream.close()

    # ---- Plain HTTP forwarding -------------------------------------------

    def _handle_http(self) -> None:
        method = self.command or "GET"
        if not self._admit(self._request_domain(), method, self.path):
            return
        try:
            with urlopen(self._upstream_request(method), timeout=UPSTREAM_TIMEOUT_SECONDS) as resp:
                status, headers, body = resp.status, resp.getheaders(), resp.read()
        except (OSError, ValueError, HTTPException) as exc:
            # urllib's HTTPError (an OSError) means upstream answered with an error status.
            # TODO(bulbi): relay upstream 4xx/5xx responses instead of mapping them to 502.
            logger.debug("HTTP forward failed for %s: %s", self.path, exc)
            self.send_error(HTTPStatus.BAD_GATEWAY, "Upstream request failed")
            return
        self.send_response(status)
        for key, value in headers:
            if key.lower() not in HOP_BY_HOP_HEADERS:
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _request_domain(self) -> str:
        host = self.headers.get("Host") or urlparse(self.path).netloc
        return host_without_port(host) if host else ""

    def _upstream_request(self, method: str) -> Request:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        request = Request(self.path, data=body, method=method)
        for key, value in self.headers.items():
            if key.lower() not in HOP_BY_HOP_HEADERS:
                request.add_header(key, value)
        return request

    do_GET = _handle_http  # noqa: N815
    do_POST = _handle_http  # noqa: N815
    do_PUT = _handle_http  # noqa: N815
    do_DELETE = _handle_http  # noqa: N815
    do_PATCH = _handle_http  # noqa: N815
    do_HEAD = _handle_http  # noqa: N815
    do_OPTIONS = _handle_http  # noqa: N815
