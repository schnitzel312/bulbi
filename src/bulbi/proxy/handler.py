"""Per-request handling for the proxy: CONNECT tunnels and plain HTTP forwarding."""

from __future__ import annotations

import logging
import select
import socket
from http import HTTPStatus
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, OpenerDirector, ProxyHandler, Request, build_opener

from bulbi.proxy.audit import AuditAction

if TYPE_CHECKING:
    from bulbi.proxy.server import ProxyContext, ProxyHTTPServer

logger = logging.getLogger(__name__)

TUNNEL_BUFFER_SIZE = 65536
UPSTREAM_TIMEOUT_SECONDS = 60
DEFAULT_TLS_PORT = 443
UNKNOWN_DOMAIN = "(unknown)"
DENIED_MESSAGE = "Domain not in allowlist"
HTTP_SCHEME = "http"

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


class _NoRedirectHandler(HTTPRedirectHandler):
    """Hand redirects back to the client, which then asks the proxy again (and is checked)."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Ignores the host's own proxy environment variables and never follows redirects.
_UPSTREAM_OPENER: OpenerDirector = build_opener(ProxyHandler({}), _NoRedirectHandler())


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """Applies the domain policy to each request, audits it, then forwards it."""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log; the audit log replaces it."""

    @property
    def _context(self) -> ProxyContext:
        return cast("ProxyHTTPServer", self.server).context

    def _admit(self, domain: str, method: str, url: str, *, permitted: bool = True) -> bool:
        """Check the policy, audit the decision, and reply 403 if denied.

        ``permitted=False`` denies regardless of the policy (a malformed request).
        """
        allowed = permitted and bool(domain) and self._context.policy.allows(domain)
        action = AuditAction.ALLOW if allowed else AuditAction.DENY
        self._context.audit.record(domain or UNKNOWN_DOMAIN, action, method, url)
        if not allowed:
            self.send_error(HTTPStatus.FORBIDDEN, DENIED_MESSAGE)
        return allowed

    # ---- CONNECT (HTTPS tunnelling) ---------------------------------------

    def do_CONNECT(self) -> None:
        if not self._admit(host_without_port(self.path).lower(), "CONNECT", self.path):
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

    # TODO(bulbi): CONNECT is checked by domain only; any port on an allowed domain is
    # permitted (e.g. allowed.com:22), not just 443.
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
        target, consistent = self._http_target()
        if not self._admit(target, method, self.path, permitted=consistent):
            return
        request = self._upstream_request(method)
        if request is None:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return
        try:
            with _UPSTREAM_OPENER.open(request, timeout=UPSTREAM_TIMEOUT_SECONDS) as response:
                self._relay_response(response.status, response.getheaders(), response.read())
        except HTTPError as error:
            # Upstream answered with a non-2xx status (redirects included): pass it on as is.
            with error:
                self._relay_response(error.code, list(error.headers.items()), error.read())
        except (OSError, ValueError, HTTPException) as exc:
            logger.debug("HTTP forward failed for %s: %s", self.path, exc)
            self.send_error(HTTPStatus.BAD_GATEWAY, "Upstream request failed")

    def _http_target(self) -> tuple[str, bool]:
        """The host the request would actually be sent to, and whether it may be sent.

        Only absolute ``http://`` URLs are forwarded, and a ``Host`` header, when present,
        must name the same host; the policy is applied to the URL's own host.
        """
        url = urlsplit(self.path)
        target = (url.hostname or "").lower()
        if url.scheme != HTTP_SCHEME or not target:
            return target, False
        host_header = self.headers.get("Host")
        if host_header and host_without_port(host_header).lower() != target:
            return target, False
        return target, True

    def _upstream_request(self, method: str) -> Request | None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return None
        body = self.rfile.read(content_length) if content_length > 0 else None
        request = Request(self.path, data=body, method=method)
        for key, value in self.headers.items():
            if key.lower() not in HOP_BY_HOP_HEADERS:
                request.add_header(key, value)
        return request

    def _relay_response(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response(status)
        for key, value in headers:
            if key.lower() not in HOP_BY_HOP_HEADERS:
                self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    do_GET = _handle_http  # noqa: N815
    do_POST = _handle_http  # noqa: N815
    do_PUT = _handle_http  # noqa: N815
    do_DELETE = _handle_http  # noqa: N815
    do_PATCH = _handle_http  # noqa: N815
    do_HEAD = _handle_http  # noqa: N815
    do_OPTIONS = _handle_http  # noqa: N815
