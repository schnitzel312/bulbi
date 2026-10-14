"""Reading firewall log entries (NFLOG over netlink) into connection events.

The ruleset tags every new-connection verdict with ``log group N prefix "bulbi|..."``.
This module subscribes to that group and decodes each packet's prefix and headers.
Parsing is defensive: anything unexpected yields no event rather than an exception.

Standard-library only: it runs in the gateway image (needs ``CAP_NET_ADMIN``).
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from bulbi.gateway.firewall import LogTag
from bulbi.gateway.rules import IPAddress, Protocol

# Linux values, spelled out because the socket module only defines them on Linux.
AF_NETLINK = 16
NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULNL_CFG_CMD_BIND = 1
NFULNL_COPY_PACKET = 2
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLMSG_ERROR = 2
_COPY_RANGE = 128
_RECV_BUFFER = 65536
_NLA_TYPE_MASK = 0x3FFF

_NLMSGHDR = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("=BBH")
_NLATTR = struct.Struct("=HH")
_IP_PROTOCOLS = {6: Protocol.TCP, 17: Protocol.UDP}
_IPV4_HEADER_MIN = 20
_IPV6_HEADER = 40


@dataclass(frozen=True)
class ConnectionAttempt:
    """A logged connection attempt: what the firewall decided and for what packet."""

    tag: LogTag
    address: IPAddress
    port: int | None
    protocol: Protocol | None


def _align(length: int) -> int:
    return (length + 3) & ~3


def _attribute(attr_type: int, payload: bytes) -> bytes:
    length = _NLATTR.size + len(payload)
    return _NLATTR.pack(length, attr_type) + payload + b"\0" * (_align(length) - length)


def config_message(group: int, sequence: int, attributes: bytes) -> bytes:
    """An NFULNL config request for ``group``."""
    message_type = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
    body = _NFGENMSG.pack(socket.AF_UNSPEC, 0, socket.htons(group)) + attributes
    header = _NLMSGHDR.pack(
        _NLMSGHDR.size + len(body), message_type, NLM_F_REQUEST | NLM_F_ACK, sequence, 0
    )
    return header + body


def bind_messages(group: int) -> list[bytes]:
    """Messages that bind ``group`` and ask for packet headers."""
    mode = struct.pack("!IBB", _COPY_RANGE, NFULNL_COPY_PACKET, 0)
    return [
        config_message(group, 1, _attribute(NFULA_CFG_CMD, bytes([NFULNL_CFG_CMD_BIND]))),
        config_message(group, 2, _attribute(NFULA_CFG_MODE, mode)),
    ]


def parse_datagram(data: bytes) -> Iterator[ConnectionAttempt]:
    """Every connection attempt in one netlink datagram (possibly several messages)."""
    offset = 0
    while offset + _NLMSGHDR.size <= len(data):
        length, message_type, _, _, _ = _NLMSGHDR.unpack_from(data, offset)
        if length < _NLMSGHDR.size or offset + length > len(data):
            return
        if message_type == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
            attempt = _parse_packet(data[offset + _NLMSGHDR.size : offset + length])
            if attempt is not None:
                yield attempt
        offset += _align(length)


def _parse_packet(body: bytes) -> ConnectionAttempt | None:
    attributes = dict(_attributes(body[_NFGENMSG.size :]))
    prefix = attributes.get(NFULA_PREFIX, b"").rstrip(b"\0").decode("ascii", "replace")
    tag = LogTag.decode(prefix)
    packet = attributes.get(NFULA_PAYLOAD)
    if tag is None or packet is None:
        return None
    return parse_ip_packet(tag, packet)


def _attributes(data: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + _NLATTR.size <= len(data):
        length, attr_type = _NLATTR.unpack_from(data, offset)
        if length < _NLATTR.size or offset + length > len(data):
            return
        yield attr_type & _NLA_TYPE_MASK, data[offset + _NLATTR.size : offset + length]
        offset += _align(length)


def parse_ip_packet(tag: LogTag, packet: bytes) -> ConnectionAttempt | None:
    """Destination address, port and protocol of an IPv4 or IPv6 packet."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= _IPV4_HEADER_MIN:  # noqa: PLR2004
        header_length = (packet[0] & 0x0F) * 4
        address: IPAddress = ipaddress.IPv4Address(packet[16:20])
        return _with_ports(tag, address, packet[9], packet[header_length:])
    if version == 6 and len(packet) >= _IPV6_HEADER:  # noqa: PLR2004
        address = ipaddress.IPv6Address(packet[24:40])
        return _with_ports(tag, address, packet[6], packet[_IPV6_HEADER:])
    return None


def _with_ports(
    tag: LogTag, address: IPAddress, protocol_number: int, transport: bytes
) -> ConnectionAttempt:
    protocol = _IP_PROTOCOLS.get(protocol_number)
    port = None
    if protocol is not None and len(transport) >= 4:  # noqa: PLR2004 - src + dst port
        (port,) = struct.unpack_from("!H", transport, 2)
    return ConnectionAttempt(tag, address, port, protocol)


class NflogReader:
    """Subscribes to an NFLOG group and yields connection attempts forever."""

    def __init__(self, group: int) -> None:
        self._group = group

    def attempts(self) -> Iterator[ConnectionAttempt]:
        with socket.socket(AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER) as sock:
            sock.bind((0, 0))
            for message in bind_messages(self._group):
                sock.send(message)
            while True:
                yield from parse_datagram(sock.recv(_RECV_BUFFER))
