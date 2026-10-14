"""The in-process forward proxy that is the sandbox's network boundary.

All HTTP and HTTPS traffic from the container is pointed at this proxy, which applies
a :class:`~bulbi.proxy.policy.DomainPolicy` and records every decision in the audit log.

Spec ``[secrets]`` are not used here: they are parsed and validated, but neither
resolved nor injected into requests, and never passed into the container.
TODO(bulbi): implement per-host secret injection for ``[secrets]`` entries.
"""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from http.server import HTTPServer
from socketserver import ThreadingMixIn

from bulbi.constants import PROXY_BIND_HOST
from bulbi.errors import SandboxError
from bulbi.proxy.audit import AuditLogWriter
from bulbi.proxy.handler import ProxyRequestHandler
from bulbi.proxy.policy import DomainPolicy

logger = logging.getLogger(__name__)

_SHUTDOWN_TIMEOUT_SECONDS = 5
# How often serve_forever checks for shutdown; bounds how long stop() blocks.
_SHUTDOWN_POLL_SECONDS = 0.1
_EPHEMERAL_PORT = 0


@dataclass(frozen=True)
class ProxyContext:
    """What every request handler needs: the policy to apply and where to audit."""

    policy: DomainPolicy
    audit: AuditLogWriter


class ProxyHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP server handling each request in a daemon thread, carrying a ProxyContext."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], context: ProxyContext) -> None:
        super().__init__(address, ProxyRequestHandler)
        self.context = context


class NetworkProxy(ABC):
    """A host-side proxy a sandbox routes its traffic through."""

    @abstractmethod
    def start(self, port: int = _EPHEMERAL_PORT) -> int:
        """Start serving; returns the bound port (``0`` picks a free one)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop serving; safe to call when not running."""


class ProxyServer(NetworkProxy):
    """Runs a :class:`ProxyHTTPServer` in a background thread."""

    def __init__(
        self,
        policy: DomainPolicy,
        audit: AuditLogWriter,
        bind_host: str = PROXY_BIND_HOST,
    ) -> None:
        self._context = ProxyContext(policy=policy, audit=audit)
        self._bind_host = bind_host
        self._server: ProxyHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, port: int = _EPHEMERAL_PORT) -> int:
        if self._server is not None:
            raise SandboxError("proxy is already running")
        self._server = ProxyHTTPServer((self._bind_host, port), self._context)
        bound_port: int = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": _SHUTDOWN_POLL_SECONDS},
            name="bulbi-proxy",
            daemon=True,
        )
        self._thread.start()
        logger.info("Proxy started on %s:%d", self._bind_host, bound_port)
        return bound_port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
            self._thread = None
            logger.info("Proxy stopped")
