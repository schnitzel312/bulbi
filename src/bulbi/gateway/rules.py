"""Network rules from ``bulbi.toml``: parsing and per-rule matching.

A rule is written ``TARGET[:PORTS][/PROTO]`` where TARGET is a domain (``pypi.org``),
a wildcard domain (``*.github.com``), an IP address or CIDR (``10.20.0.0/16``,
``[2001:db8::1]``), or the keyword ``host`` (the machine running Bulbi). PORTS is a
comma-separated list of ports and ``lo-hi`` ranges; no ports means all ports. PROTO
is ``tcp`` or ``udp``; no protocol means both. IPv6 targets with ports must be
bracketed: ``[2001:db8::/32]:443``.

This module is standard-library only: it also runs inside the gateway image.
"""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum

from bulbi.errors import RuleError

HOST_KEYWORD = "host"
WILDCARD_PREFIX = "*."
MIN_PORT = 0
MAX_PORT = 65535
_PORT_LIST_SEPARATOR = ","
_PORT_RANGE_SEPARATOR = "-"
_PROTO_SEPARATOR = "/"
_LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_MAX_DOMAIN_LENGTH = 253

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


ALL_PROTOCOLS: frozenset[Protocol] = frozenset(Protocol)


@dataclass(frozen=True, order=True)
class PortRange:
    """An inclusive range of ports."""

    low: int
    high: int

    def __contains__(self, port: object) -> bool:
        return isinstance(port, int) and self.low <= port <= self.high

    def __str__(self) -> str:
        return str(self.low) if self.low == self.high else f"{self.low}-{self.high}"


ALL_PORTS = PortRange(MIN_PORT, MAX_PORT)


@dataclass(frozen=True)
class PortSpec:
    """The ports a rule covers; no ranges means every port."""

    ranges: tuple[PortRange, ...] = ()

    @property
    def is_all(self) -> bool:
        return not self.ranges

    def __contains__(self, port: object) -> bool:
        return self.is_all or any(port in port_range for port_range in self.ranges)

    def effective_ranges(self) -> tuple[PortRange, ...]:
        return self.ranges or (ALL_PORTS,)

    def __str__(self) -> str:
        return _PORT_LIST_SEPARATOR.join(str(r) for r in self.ranges)


def normalize_address(address: IPAddress) -> IPAddress:
    """IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are treated as their IPv4 form."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class Rule(ABC):
    """One allow or deny entry. Subclasses define what target the rule names."""

    def __init__(self, text: str, ports: PortSpec, protocols: frozenset[Protocol]) -> None:
        self.text = text
        self.ports = ports
        self.protocols = protocols

    def applies_to(self, port: int, protocol: Protocol) -> bool:
        """Whether the rule's port and protocol restrictions include this connection."""
        return protocol in self.protocols and port in self.ports

    @property
    def target_specificity(self) -> int:
        """How narrow the target is; compared only between rules of the same family."""
        return 0

    def specificity(self) -> tuple[int, int, int]:
        """Sort key: target first, then "has a port", then "has a protocol"."""
        return (
            self.target_specificity,
            int(not self.ports.is_all),
            int(self.protocols != ALL_PROTOCOLS),
        )

    @property
    @abstractmethod
    def kind(self) -> str:
        """Short label for reports (``domain``, ``address``, ``host``)."""

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.text!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Rule) and self.canonical() == other.canonical()

    def __hash__(self) -> int:
        return hash(self.canonical())

    def canonical(self) -> tuple[str, str, tuple[PortRange, ...], tuple[str, ...]]:
        """Identity of the rule regardless of how it was written."""
        return (
            self.kind,
            self.target_text(),
            tuple(sorted(self.ports.ranges)),
            tuple(sorted(self.protocols)),
        )

    @abstractmethod
    def target_text(self) -> str:
        """The target part of the rule in canonical form."""


class DomainRule(Rule):
    """``name`` (exact) or ``*.name`` (any subdomain, not the apex)."""

    def __init__(
        self,
        text: str,
        name: str,
        wildcard: bool,
        ports: PortSpec,
        protocols: frozenset[Protocol],
    ) -> None:
        super().__init__(text, ports, protocols)
        self.name = name
        self.wildcard = wildcard

    @property
    def kind(self) -> str:
        return "domain"

    def target_text(self) -> str:
        return f"{WILDCARD_PREFIX}{self.name}" if self.wildcard else self.name

    def matches_name(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        if self.wildcard:
            return name.endswith(f".{self.name}")
        return name == self.name

    @property
    def target_specificity(self) -> int:
        # Exact beats every wildcard; longer wildcards beat shorter ones.
        labels = self.name.count(".") + 1
        return 1_000 if not self.wildcard else labels


class AddressRule(Rule):
    """An IP address or CIDR range (IPv4 or IPv6)."""

    def __init__(
        self, text: str, network: IPNetwork, ports: PortSpec, protocols: frozenset[Protocol]
    ) -> None:
        super().__init__(text, ports, protocols)
        self.network = network

    @property
    def kind(self) -> str:
        return "address"

    def target_text(self) -> str:
        return str(self.network)

    def matches_address(self, address: IPAddress, host_addresses: frozenset[IPAddress]) -> bool:
        address = normalize_address(address)
        return address.version == self.network.version and address in self.network

    @property
    def target_specificity(self) -> int:
        return self.network.prefixlen


class HostRule(Rule):
    """``host``: the machine running Bulbi, however the box reaches it."""

    @property
    def kind(self) -> str:
        return HOST_KEYWORD

    def target_text(self) -> str:
        return HOST_KEYWORD

    def matches_address(self, address: IPAddress, host_addresses: frozenset[IPAddress]) -> bool:
        return normalize_address(address) in host_addresses

    @property
    def target_specificity(self) -> int:
        return 128  # As narrow as a single address.


AddressLikeRule = AddressRule | HostRule


class RuleParser:
    """Parses rule strings, raising :class:`RuleError` with the offending text."""

    def parse(self, text: str) -> Rule:
        if not isinstance(text, str):
            raise RuleError(f"network rule must be a string, got {text!r}")
        raw = text.strip()
        if not raw:
            raise RuleError("network rule is empty")
        body, protocols = self._split_protocol(raw, text)
        target, ports = self._split_ports(body, text)
        port_spec = self._parse_ports(ports, text) if ports is not None else PortSpec()
        return self._build(text, target, port_spec, protocols)

    @staticmethod
    def _split_protocol(raw: str, text: str) -> tuple[str, frozenset[Protocol]]:
        head, separator, tail = raw.rpartition(_PROTO_SEPARATOR)
        if separator and tail.lower() in {p.value for p in Protocol}:
            if not head:
                raise RuleError(f"invalid network rule '{text}': missing target")
            return head, frozenset({Protocol(tail.lower())})
        return raw, ALL_PROTOCOLS

    @staticmethod
    def _split_ports(body: str, text: str) -> tuple[str, str | None]:
        if body.startswith("["):
            end = body.find("]")
            if end == -1:
                raise RuleError(f"invalid network rule '{text}': unclosed '['")
            target, rest = body[1:end], body[end + 1 :]
            if not rest:
                return target, None
            if not rest.startswith(":") or len(rest) == 1:
                raise RuleError(f"invalid network rule '{text}': expected ':PORTS' after ']'")
            return target, rest[1:]
        if body.count(":") > 1:
            return body, None  # A bare IPv6 address or CIDR: no ports.
        target, separator, ports = body.partition(":")
        if separator and not ports:
            raise RuleError(f"invalid network rule '{text}': empty port list")
        return target, ports if separator else None

    @staticmethod
    def _parse_ports(ports: str, text: str) -> PortSpec:
        ranges = []
        for item in ports.split(_PORT_LIST_SEPARATOR):
            low_text, separator, high_text = item.strip().partition(_PORT_RANGE_SEPARATOR)
            try:
                low = int(low_text)
                high = int(high_text) if separator else low
            except ValueError:
                raise RuleError(f"invalid port '{item}' in network rule '{text}'") from None
            if not MIN_PORT < low <= high <= MAX_PORT:
                raise RuleError(f"invalid port '{item}' in network rule '{text}'")
            ranges.append(PortRange(low, high))
        return PortSpec(tuple(sorted(set(ranges))))

    def _build(
        self, text: str, target: str, ports: PortSpec, protocols: frozenset[Protocol]
    ) -> Rule:
        lowered = target.strip().lower()
        if lowered == HOST_KEYWORD:
            return HostRule(text, ports, protocols)
        network = self._as_network(lowered, text)
        if network is not None:
            return AddressRule(text, network, ports, protocols)
        wildcard = lowered.startswith(WILDCARD_PREFIX)
        name = lowered.removeprefix(WILDCARD_PREFIX).rstrip(".")
        self._validate_domain(name, text)
        return DomainRule(text, name, wildcard, ports, protocols)

    @staticmethod
    def _as_network(target: str, text: str) -> IPNetwork | None:
        looks_like_address = ":" in target or (
            target.replace(".", "").replace("/", "").isdigit() and target[:1].isdigit()
        )
        if not looks_like_address:
            return None
        try:
            network = ipaddress.ip_network(target, strict=True)
        except ValueError as exc:
            raise RuleError(f"invalid address in network rule '{text}': {exc}") from None
        if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped:
            mapped = network.network_address.ipv4_mapped
            prefix = max(network.prefixlen - 96, 0)
            return ipaddress.ip_network(f"{mapped}/{prefix}", strict=False)
        return network

    @staticmethod
    def _validate_domain(name: str, text: str) -> None:
        labels = name.split(".")
        valid = (
            0 < len(name) <= _MAX_DOMAIN_LENGTH
            and len(labels) >= 1
            and all(_LABEL_PATTERN.match(label) for label in labels)
        )
        if not valid:
            raise RuleError(f"invalid domain in network rule '{text}'")
