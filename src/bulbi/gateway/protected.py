"""Local and private address ranges that only explicit address rules may reach."""

from __future__ import annotations

import ipaddress

from bulbi.gateway.rules import IPAddress, IPNetwork, normalize_address

# Loopback, RFC 1918, CGNAT, link-local (incl. cloud metadata 169.254.169.254),
# multicast, documentation/benchmark/reserved ranges, and their IPv6 counterparts.
# Docker's default address pools (172.17.0.0/16 and up, 192.168.0.0/16) fall inside.
PROTECTED_NETWORKS: tuple[IPNetwork, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def is_protected(address: IPAddress) -> bool:
    """Whether ``address`` (IPv4-mapped forms included) is local, private or reserved."""
    address = normalize_address(address)
    return any(
        address.version == network.version and address in network for network in PROTECTED_NETWORKS
    )


def overlaps_protected(network: IPNetwork) -> bool:
    """Whether an address rule's range reaches into any protected range."""
    return any(
        network.version == protected.version and network.overlaps(protected)  # type: ignore[arg-type,unused-ignore]
        for protected in PROTECTED_NETWORKS
    )
