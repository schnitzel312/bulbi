"""Gateway container entry point: ``python3 -m bulbi.gateway.daemon``.

Startup order matters:
1. resolve the host's address, if needed, while the namespace is still open;
2. load the ruleset atomically (from then on the namespace is locked down);
3. bind the resolver sockets as root, fork, and drop the child to the resolver uid;
4. follow the firewall log and the resolver pipe, then write the ready file.

If the resolver dies the supervisor exits, the container stops and the box loses its
network (fail closed, R6).

Standard-library only: it runs in the gateway image.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
from pathlib import Path

from bulbi.gateway.audit import AuditLogWriter
from bulbi.gateway.config import (
    CONFIG_ENV,
    DOCKER_DESKTOP_HOST_NAME,
    READY_FILE,
    GatewayConfig,
    HostAccess,
)
from bulbi.gateway.firewall import (
    LOG_GROUP,
    RESOLVER_PORT,
    FirewallContext,
    NftablesBackend,
    unique_addresses,
)
from bulbi.gateway.nflog import NflogReader
from bulbi.gateway.policy import NetworkPolicy, PolicyMatcher
from bulbi.gateway.resolver import DnsServer, DockerDnsUpstream, Resolver
from bulbi.gateway.rules import IPAddress
from bulbi.gateway.supervisor import FirewallLoader, PipeSink, Supervisor

logger = logging.getLogger("bulbi.gateway")

RESOLVER_HOST = "127.0.0.1"
_SOCKET_BACKLOG = 64


def host_addresses(config: GatewayConfig) -> tuple[IPAddress, ...]:
    """Addresses that mean "the machine running Bulbi" from inside the box."""
    if config.host_access is HostAccess.BRIDGE_RELAY:
        return unique_addresses([config.host_address] if config.host_address else [])
    try:
        infos = socket.getaddrinfo(DOCKER_DESKTOP_HOST_NAME, None)
    except OSError:
        logger.warning("could not resolve %s; host rules inactive", DOCKER_DESKTOP_HOST_NAME)
        return ()
    return unique_addresses([str(info[4][0]) for info in infos])


def _bind_resolver_sockets() -> tuple[socket.socket, socket.socket]:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((RESOLVER_HOST, RESOLVER_PORT))
    tcp = socket.create_server((RESOLVER_HOST, RESOLVER_PORT), backlog=_SOCKET_BACKLOG)
    return udp, tcp


def _run_resolver(
    config: GatewayConfig,
    matcher: PolicyMatcher,
    sockets: tuple[socket.socket, socket.socket],
    pipe_fd: int,
) -> None:
    """Child process: drop privileges for good, then serve DNS forever."""
    os.setgroups([])
    os.setgid(config.resolver_uid)
    os.setuid(config.resolver_uid)
    sink = PipeSink(os.fdopen(pipe_fd, "w"))
    resolver = Resolver(matcher, DockerDnsUpstream(), sink)
    try:
        DnsServer(resolver, *sockets).serve_forever()
    finally:
        os._exit(1)


def _follow_firewall_log(supervisor: Supervisor) -> None:
    for attempt in NflogReader(LOG_GROUP).attempts():
        supervisor.record_attempt(attempt)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="bulbi-gateway: %(message)s")
    config = GatewayConfig.from_json(os.environ[CONFIG_ENV])
    policy = NetworkPolicy.parse(config.default, config.allow, config.deny)
    hosts = host_addresses(config)
    matcher = PolicyMatcher(policy, frozenset(hosts))
    backend = NftablesBackend()
    loader = FirewallLoader()
    loader.load(backend.render(policy, FirewallContext(config.resolver_uid, hosts)))
    logger.info("ruleset loaded (%d rules, host %s)", len(policy.rules), list(map(str, hosts)))

    sockets = _bind_resolver_sockets()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        _run_resolver(config, matcher, sockets, write_fd)
    os.close(write_fd)
    for sock in sockets:
        sock.close()

    audit = AuditLogWriter(Path(config.log_file), config.log_owner)
    supervisor = Supervisor(policy, matcher, backend, loader, audit)
    threading.Thread(target=_follow_firewall_log, args=(supervisor,), daemon=True).start()
    pipe = os.fdopen(read_fd)
    threading.Thread(target=supervisor.consume, args=(pipe,), daemon=True).start()
    Path(READY_FILE).write_text("ready\n")
    logger.info("ready")
    _, status = os.waitpid(child, 0)
    logger.error("resolver exited with status %d; stopping the gateway", status)
    return 1


if __name__ == "__main__":
    sys.exit(main())
