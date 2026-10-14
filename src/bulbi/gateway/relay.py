"""Host-side TCP relay for ``host:`` rules on Linux (spec §3.3).

On Linux the box cannot reach services bound to the host's ``127.0.0.1``. The CLI runs
this relay on the dedicated bridge's gateway address, one listener per port named in a
``host:`` allow rule. It only accepts connections from the gateway container's address
and forwards them to ``127.0.0.1:<same port>``. (Docker Desktop already provides this
through ``host.docker.internal``, so macOS does not use the relay.)

Standard-library only.
"""

from __future__ import annotations

import logging
import selectors
import socket
import threading
from collections.abc import Iterable

logger = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
_BUFFER = 65536
_ACCEPT_POLL_SECONDS = 0.2
_CONNECT_TIMEOUT_SECONDS = 5.0


class HostRelay:
    """Relays TCP from the gateway to host-local services on declared ports only."""

    def __init__(self, bind_host: str, ports: Iterable[int], target_host: str = LOOPBACK) -> None:
        self._bind_host = bind_host
        self._ports = sorted(set(ports))
        self._target_host = target_host
        self._allowed_source: str | None = None
        self._listeners: list[socket.socket] = []
        self._stopping = threading.Event()

    @property
    def ports(self) -> list[int]:
        return list(self._ports)

    def allow_source(self, address: str) -> None:
        """Accept connections from ``address`` (the gateway); until then accept none."""
        self._allowed_source = address

    def start(self) -> None:
        for port in self._ports:
            listener = socket.create_server((self._bind_host, port), reuse_port=False)
            listener.settimeout(_ACCEPT_POLL_SECONDS)
            self._listeners.append(listener)
            threading.Thread(
                target=self._accept_loop, args=(listener, port), name=f"relay-{port}", daemon=True
            ).start()

    def stop(self) -> None:
        self._stopping.set()
        for listener in self._listeners:
            listener.close()
        self._listeners.clear()

    def _accept_loop(self, listener: socket.socket, port: int) -> None:
        while not self._stopping.is_set():
            try:
                client, (source, *_) = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if source != self._allowed_source:
                logger.warning("relay: refused connection from %s to port %d", source, port)
                client.close()
                continue
            threading.Thread(target=self._relay, args=(client, port), daemon=True).start()

    def _relay(self, client: socket.socket, port: int) -> None:
        try:
            upstream = socket.create_connection(
                (self._target_host, port), timeout=_CONNECT_TIMEOUT_SECONDS
            )
        except OSError:
            client.close()
            return
        with client, upstream:
            _pump(client, upstream)


def _pump(first: socket.socket, second: socket.socket) -> None:
    """Copy bytes both ways until either side closes."""
    for sock in (first, second):
        sock.settimeout(None)
    with selectors.DefaultSelector() as selector:
        selector.register(first, selectors.EVENT_READ, second)
        selector.register(second, selectors.EVENT_READ, first)
        while True:
            for key, _ in selector.select():
                source: socket.socket = key.fileobj  # type: ignore[assignment]
                try:
                    data = source.recv(_BUFFER)
                    if not data:
                        return
                    key.data.sendall(data)
                except OSError:
                    return
