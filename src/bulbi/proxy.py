"""HTTP CONNECT proxy with domain allowlist.

This proxy is the network security boundary for Bulbi containers.
All HTTP/HTTPS traffic from the container is routed through this proxy,
which enforces a domain allowlist before forwarding requests.
"""

from __future__ import annotations

import json
import logging
import os
import select
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from bulbi.spec import SecretSpec

logger = logging.getLogger(__name__)

_TUNNEL_BUFSIZE = 65536
_TUNNEL_TIMEOUT = 60


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer that handles each request in a new thread."""

    daemon_threads = True
    allow_reuse_address = True


def _extract_domain(host_string: str) -> str:
    """Extract the domain from a host:port string, stripping the port."""
    # Handle IPv6 addresses in brackets
    if host_string.startswith("["):
        bracket_end = host_string.find("]")
        if bracket_end != -1:
            return host_string[1:bracket_end]
        return host_string
    if ":" in host_string:
        return host_string.rsplit(":", 1)[0]
    return host_string


def _log_request(
    log_path: Path,
    domain: str,
    action: str,
    method: str,
    url: str,
) -> None:
    """Append a structured JSON log line to the log file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "action": action,
        "method": method,
        "url": url,
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        logger.exception("Failed to write proxy log entry")


def _make_handler_class(
    allowed_domains: set[str],
    secrets: dict[str, SecretSpec],
    log_path: Path,
) -> type[BaseHTTPRequestHandler]:
    """Create a request handler class closed over the proxy configuration."""

    class ProxyHandler(BaseHTTPRequestHandler):
        """Handles both CONNECT (HTTPS) and plain HTTP requests."""

        # Suppress default stderr logging — we do our own structured logging.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

        # ---- domain check ----

        def _is_allowed(self, domain: str) -> bool:
            return domain in allowed_domains

        # ---- CONNECT (HTTPS tunneling) ----

        def do_CONNECT(self) -> None:  # noqa: N802
            domain = _extract_domain(self.path)
            if not self._is_allowed(domain):
                _log_request(log_path, domain, "deny", "CONNECT", self.path)
                self.send_error(403, "Domain not in allowlist")
                return

            _log_request(log_path, domain, "allow", "CONNECT", self.path)

            # Parse host and port from CONNECT target.
            host, _, port_str = self.path.rpartition(":")
            if not host:
                # No port specified — default to 443 for CONNECT.
                host = self.path
                port = 443
            else:
                try:
                    port = int(port_str)
                except ValueError:
                    self.send_error(400, "Invalid port")
                    return

            # Connect to the upstream server.
            try:
                upstream = socket.create_connection((host, port), timeout=_TUNNEL_TIMEOUT)
            except OSError as exc:
                logger.debug("CONNECT upstream failed for %s: %s", self.path, exc)
                self.send_error(502, "Failed to connect to upstream")
                return

            # Tell the client the tunnel is established.
            self.send_response(200, "Connection Established")
            self.end_headers()

            # Shuttle bytes between client and upstream using select().
            client_conn = self.connection
            self._tunnel(client_conn, upstream)

        def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
            """Bidirectionally shuttle bytes until one side closes."""
            try:
                client.setblocking(False)
                upstream.setblocking(False)
                sockets = [client, upstream]
                while True:
                    readable, _, errors = select.select(sockets, [], sockets, _TUNNEL_TIMEOUT)
                    if errors:
                        break
                    if not readable:
                        # Timeout — tear down.
                        break
                    for sock in readable:
                        other = upstream if sock is client else client
                        try:
                            data = sock.recv(_TUNNEL_BUFSIZE)
                        except OSError:
                            data = b""
                        if not data:
                            return
                        try:
                            other.sendall(data)
                        except OSError:
                            return
            finally:
                try:
                    upstream.close()
                except OSError:
                    pass

        # ---- Plain HTTP forwarding ----

        def _handle_http(self) -> None:
            """Forward a plain HTTP request after allowlist check."""
            # Determine the target domain from the Host header or URL.
            host_header = self.headers.get("Host", "")
            if host_header:
                domain = _extract_domain(host_header)
            else:
                parsed = urlparse(self.path)
                domain = _extract_domain(parsed.netloc) if parsed.netloc else ""

            url = self.path
            method = self.command or "GET"

            if not domain or not self._is_allowed(domain):
                _log_request(log_path, domain or "(unknown)", "deny", method, url)
                self.send_error(403, "Domain not in allowlist")
                return

            _log_request(log_path, domain, "allow", method, url)

            # Read the request body if present.
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # Build the forwarded request.
            req = Request(url, data=body, method=method)
            # Copy headers, skipping hop-by-hop headers.
            hop_by_hop = {
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
            for key, value in self.headers.items():
                if key.lower() not in hop_by_hop:
                    req.add_header(key, value)

            try:
                with urlopen(req, timeout=_TUNNEL_TIMEOUT) as resp:  # noqa: S310
                    status = resp.status
                    resp_headers = resp.getheaders()
                    resp_body = resp.read()
            except Exception as exc:
                logger.debug("HTTP forward failed for %s: %s", url, exc)
                self.send_error(502, "Upstream request failed")
                return

            self.send_response(status)
            for key, value in resp_headers:
                if key.lower() not in hop_by_hop:
                    self.send_header(key, value)
            self.end_headers()
            if resp_body:
                self.wfile.write(resp_body)

        # Map all standard HTTP methods to the same handler.
        do_GET = _handle_http  # noqa: N815
        do_POST = _handle_http  # noqa: N815
        do_PUT = _handle_http  # noqa: N815
        do_DELETE = _handle_http  # noqa: N815
        do_PATCH = _handle_http  # noqa: N815
        do_HEAD = _handle_http  # noqa: N815
        do_OPTIONS = _handle_http  # noqa: N815

    return ProxyHandler


class AllowlistProxy:
    """Threaded HTTP proxy that enforces a domain allowlist.

    Args:
        allowed_domains: Domains that are permitted (exact match).
        secrets: Secret specs keyed by name. Env-sourced secrets are
                 resolved eagerly so the host env var is captured.
        log_path: Path for the structured JSON request log.
    """

    def __init__(
        self,
        allowed_domains: list[str],
        secrets: dict[str, SecretSpec],
        log_path: Path,
    ) -> None:
        self._allowed_domains: set[str] = set(allowed_domains)
        self._log_path = log_path
        self._server: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

        # Eagerly resolve env-sourced secrets so they are available for
        # future header-injection (v2).  We intentionally do NOT pass
        # these values into the container.
        self._resolved_secrets: dict[str, str | None] = {}
        for name, spec in secrets.items():
            if spec.from_source == "env":
                self._resolved_secrets[name] = os.environ.get(name)

    def start(self, port: int = 0) -> int:
        """Start the proxy server in a daemon thread.

        Args:
            port: TCP port to listen on. Pass 0 to auto-assign.

        Returns:
            The actual port the server is listening on.
        """
        if self._server is not None:
            raise RuntimeError("Proxy is already running")

        # Ensure log directory exists.
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        handler_class = _make_handler_class(
            self._allowed_domains,
            {},  # secrets not yet injected into handler (v1)
            self._log_path,
        )
        self._server = _ThreadingHTTPServer(("127.0.0.1", port), handler_class)
        actual_port = self._server.server_address[1]

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="bulbi-proxy",
            daemon=True,
        )
        self._thread.start()
        logger.info("Allowlist proxy started on port %d", actual_port)
        return actual_port

    def stop(self) -> None:
        """Shut down the proxy server gracefully."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("Allowlist proxy stopped")


def get_denied_requests(log_path: Path) -> list[dict[str, Any]]:
    """Read the proxy log and return only denied entries.

    Args:
        log_path: Path to the JSON-lines proxy log file.

    Returns:
        List of log entries where the action was "deny".
    """
    denied: list[dict[str, Any]] = []
    if not log_path.exists():
        return denied
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("action") == "deny":
                denied.append(entry)
    return denied
