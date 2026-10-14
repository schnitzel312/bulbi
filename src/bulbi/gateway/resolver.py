"""The box's DNS resolver: policy first, then upstream, then answer vetting (spec §3.2).

* A name no rule allows gets ``NXDOMAIN`` without any upstream query (R5).
* Allowed names are resolved upstream; protected addresses are stripped from the
  answer unless an address/host rule allows them (R2).
* Every surviving address is reported to a :class:`ResolverSink`, which pins it in the
  firewall for the name's allowed ports (or blocks it, for denied names in blacklist
  mode).

Standard-library only: it runs, unprivileged, inside the gateway image.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, replace

from bulbi.gateway.audit import LogEntry, timestamp
from bulbi.gateway.dns import (
    DnsFormatError,
    DnsMessage,
    RecordType,
    ResourceRecord,
    ResponseCode,
)
from bulbi.gateway.firewall import DNS_PORT, DOCKER_EMBEDDED_DNS, AddressEntry, PinKind
from bulbi.gateway.policy import (
    HOST_NAME,
    Action,
    Decision,
    NameCoverage,
    PolicyMatcher,
    Reason,
)
from bulbi.gateway.protected import is_protected
from bulbi.gateway.rules import IPAddress, Protocol

logger = logging.getLogger(__name__)

DNS_METHOD = "DNS"
MALFORMED_NAME = "(malformed)"
HOST_RECORD_TTL = 60
_UPSTREAM_TIMEOUT_SECONDS = 3.0
_MAX_UDP_MESSAGE = 4096
_TCP_LENGTH = struct.Struct("!H")
_ADDRESS_VERSIONS = {int(RecordType.A): 4, int(RecordType.AAAA): 6}


class UpstreamError(Exception):
    """The upstream resolver could not answer."""


class Upstream(ABC):
    """Where allowed queries are forwarded."""

    @abstractmethod
    def query(self, payload: bytes) -> bytes:
        """Send a raw DNS query and return the raw response; raise UpstreamError."""


class DockerDnsUpstream(Upstream):
    """Docker's embedded DNS server, over UDP with a TCP retry for truncated answers."""

    def __init__(
        self,
        host: str = DOCKER_EMBEDDED_DNS,
        port: int = DNS_PORT,
        timeout: float = _UPSTREAM_TIMEOUT_SECONDS,
    ) -> None:
        self._address = (host, port)
        self._timeout = timeout

    def query(self, payload: bytes) -> bytes:
        try:
            response = self._udp(payload)
            if DnsMessage.parse(response).truncated:
                response = self._tcp(payload)
        except (OSError, DnsFormatError) as exc:
            raise UpstreamError(str(exc)) from exc
        return response

    def _udp(self, payload: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self._timeout)
            sock.sendto(payload, self._address)
            return sock.recv(_MAX_UDP_MESSAGE)

    def _tcp(self, payload: bytes) -> bytes:
        with socket.create_connection(self._address, timeout=self._timeout) as sock:
            sock.sendall(_TCP_LENGTH.pack(len(payload)) + payload)
            return read_tcp_message(sock)


def read_tcp_message(sock: socket.socket) -> bytes:
    """Read one length-prefixed DNS-over-TCP message."""
    (length,) = _TCP_LENGTH.unpack(_read_exactly(sock, _TCP_LENGTH.size))
    return _read_exactly(sock, length)


def _read_exactly(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("connection closed mid-message")
        data += chunk
    return data


class ResolverSink(ABC):
    """Receives what the resolver learns and what it wants audited."""

    @abstractmethod
    def learned(self, name: str, records: list[tuple[IPAddress, int]]) -> None:
        """``name`` resolved to these (address, ttl) pairs, already vetted."""

    @abstractmethod
    def audit(self, entry: LogEntry) -> None:
        """Record one DNS event."""


def address_entries(
    matcher: PolicyMatcher, coverage: NameCoverage, address: IPAddress, ttl: int
) -> list[AddressEntry]:
    """Firewall entries for one vetted answer of a name.

    Ports allowed by a rule are pinned. In blacklist mode, ports denied by a rule are
    blocked, so a denied name's current addresses are refused even by raw IP.
    """
    entries = []
    pinned = coverage.segments_where(Action.ALLOW, Reason.ALLOWED_BY_RULE)
    if pinned:
        entries.append(AddressEntry(address, tuple(pinned), ttl, PinKind.ALLOW))
    if matcher.policy.default is Action.ALLOW:
        blocked = coverage.segments_where(Action.DENY, Reason.DENIED_BY_RULE)
        if blocked:
            entries.append(AddressEntry(address, tuple(blocked), ttl, PinKind.DENY))
    return entries


@dataclass(frozen=True)
class _Answer:
    response: bytes
    decision: Decision
    addresses: tuple[IPAddress, ...] = ()


class Resolver:
    """Answers one DNS query according to the policy."""

    def __init__(
        self,
        matcher: PolicyMatcher,
        upstream: Upstream,
        sink: ResolverSink,
        clock: Callable[[], str] = timestamp,
    ) -> None:
        self._matcher = matcher
        self._upstream = upstream
        self._sink = sink
        self._timestamp = clock

    def answer(self, query: bytes, transport: Protocol) -> bytes | None:
        """The response to send, or ``None`` when the query is too broken to answer."""
        try:
            message = DnsMessage.parse(query)
        except DnsFormatError:
            self._audit(MALFORMED_NAME, Decision(Action.DENY, Reason.DENIED_MALFORMED), transport)
            return None
        if message.is_response or len(message.questions) != 1:
            self._audit(MALFORMED_NAME, Decision(Action.DENY, Reason.DENIED_MALFORMED), transport)
            return message.reply(ResponseCode.FORMERR).encode()
        name = message.questions[0].name.lower().rstrip(".")
        result = self._resolve(message, name, query)
        self._audit(name, result.decision, transport, result.addresses)
        return result.response

    def _resolve(self, message: DnsMessage, name: str, query: bytes) -> _Answer:
        coverage = self._matcher.name_coverage(name)
        if not coverage.resolvable:
            return _Answer(message.reply(ResponseCode.NXDOMAIN).encode(), coverage.decision)
        if name == HOST_NAME:
            return self._host_answer(message, coverage)
        try:
            response = DnsMessage.parse(self._upstream.query(query))
        except (UpstreamError, DnsFormatError) as exc:
            logger.warning("upstream DNS failed for %s: %s", name, exc)
            return _Answer(message.reply(ResponseCode.SERVFAIL).encode(), coverage.decision)
        kept = tuple(record for record in response.answers if self._keep(record))
        addresses = tuple(r.address for r in kept if r.address is not None)
        self._sink.learned(name, [(r.address, r.ttl) for r in kept if r.address is not None])
        filtered = response.with_answers(kept) if len(kept) != len(response.answers) else response
        reply = replace(filtered, id=message.id, questions=message.questions)
        return _Answer(reply.encode(), coverage.decision, addresses)

    def _keep(self, record: ResourceRecord) -> bool:
        address = record.address
        if address is None:
            return True
        return not is_protected(address) or self._matcher.address_allowed_by_rule(address)

    def _host_answer(self, message: DnsMessage, coverage: NameCoverage) -> _Answer:
        wanted = _ADDRESS_VERSIONS.get(message.questions[0].qtype)
        addresses = tuple(
            a for a in sorted(self._matcher.host_addresses, key=str) if a.version == wanted
        )
        records = tuple(
            ResourceRecord.for_address(HOST_NAME, address, HOST_RECORD_TTL)
            for address in addresses
        )
        return _Answer(
            message.reply(ResponseCode.NOERROR, records).encode(), coverage.decision, addresses
        )

    def _audit(
        self,
        name: str,
        decision: Decision,
        transport: Protocol,
        addresses: tuple[IPAddress, ...] = (),
    ) -> None:
        self._sink.audit(
            LogEntry(
                timestamp=self._timestamp(),
                domain=name,
                action=decision.action,
                method=DNS_METHOD,
                url=name,
                reason=decision.reason,
                rule=None if decision.rule is None else str(decision.rule),
                ip=",".join(str(a) for a in addresses) or None,
                proto=transport,
            )
        )


class DnsServer:
    """Serves a :class:`Resolver` on already-bound UDP and TCP sockets."""

    def __init__(
        self, resolver: Resolver, udp_socket: socket.socket, tcp_socket: socket.socket
    ) -> None:
        self._resolver = resolver
        self._udp = udp_socket
        self._tcp = tcp_socket

    def serve_forever(self) -> None:
        threading.Thread(target=self._serve_tcp, name="dns-tcp", daemon=True).start()
        self._serve_udp()

    def _serve_udp(self) -> None:
        while True:
            query, client = self._udp.recvfrom(_MAX_UDP_MESSAGE)
            threading.Thread(target=self._answer_udp, args=(query, client), daemon=True).start()

    def _answer_udp(self, query: bytes, client: tuple[str, int]) -> None:
        response = self._resolver.answer(query, Protocol.UDP)
        if response is not None:
            self._udp.sendto(response, client)

    def _serve_tcp(self) -> None:
        while True:
            connection, _ = self._tcp.accept()
            threading.Thread(target=self._answer_tcp, args=(connection,), daemon=True).start()

    def _answer_tcp(self, connection: socket.socket) -> None:
        with connection:
            try:
                connection.settimeout(_UPSTREAM_TIMEOUT_SECONDS * 2)
                while True:
                    query = read_tcp_message(connection)
                    response = self._resolver.answer(query, Protocol.TCP)
                    if response is None:
                        return
                    connection.sendall(_TCP_LENGTH.pack(len(response)) + response)
            except OSError:
                return
