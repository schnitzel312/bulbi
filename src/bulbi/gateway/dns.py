"""A small DNS message codec (RFC 1035), enough for a filtering forwarder.

Messages are parsed with name compression resolved, so answers can be filtered and
re-encoded (without compression). Standard-library only: it runs in the gateway image.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field, replace
from enum import IntEnum

from bulbi.gateway.rules import IPAddress

_HEADER = struct.Struct("!HHHHHH")
_RR_FIXED = struct.Struct("!HHIH")
_QUESTION_FIXED = struct.Struct("!HH")
_POINTER_MASK = 0xC0
_MAX_POINTER_JUMPS = 64
_MAX_LABEL = 63
_QR_FLAG = 0x8000
_OPCODE_MASK = 0x7800
_RD_FLAG = 0x0100
_RA_FLAG = 0x0080
_TC_FLAG = 0x0200
_RCODE_MASK = 0x000F
_CLASS_IN = 1


class RecordType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    AAAA = 28
    SRV = 33


class ResponseCode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    REFUSED = 5


class DnsFormatError(ValueError):
    """The bytes are not a DNS message this codec understands."""


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int = _CLASS_IN


@dataclass(frozen=True)
class ResourceRecord:
    """A record with its RDATA already decompressed (safe to re-encode as is)."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes

    @property
    def address(self) -> IPAddress | None:
        if self.rtype == RecordType.A and len(self.rdata) == 4:  # noqa: PLR2004
            return ipaddress.IPv4Address(self.rdata)
        if self.rtype == RecordType.AAAA and len(self.rdata) == 16:  # noqa: PLR2004
            return ipaddress.IPv6Address(self.rdata)
        return None

    @classmethod
    def for_address(cls, name: str, address: IPAddress, ttl: int) -> ResourceRecord:
        rtype = RecordType.A if address.version == 4 else RecordType.AAAA  # noqa: PLR2004
        return cls(name, rtype, _CLASS_IN, ttl, address.packed)


@dataclass(frozen=True)
class DnsMessage:
    id: int
    flags: int
    questions: tuple[Question, ...] = ()
    answers: tuple[ResourceRecord, ...] = ()
    authority: tuple[ResourceRecord, ...] = ()
    additional: tuple[ResourceRecord, ...] = field(default=())

    @property
    def rcode(self) -> int:
        return self.flags & _RCODE_MASK

    @property
    def is_response(self) -> bool:
        return bool(self.flags & _QR_FLAG)

    @property
    def truncated(self) -> bool:
        return bool(self.flags & _TC_FLAG)

    def reply(self, rcode: ResponseCode, answers: tuple[ResourceRecord, ...] = ()) -> DnsMessage:
        """A response to this query carrying ``rcode`` and ``answers``."""
        flags = _QR_FLAG | (self.flags & (_OPCODE_MASK | _RD_FLAG)) | _RA_FLAG | int(rcode)
        return DnsMessage(self.id, flags, self.questions, answers)

    def with_answers(self, answers: tuple[ResourceRecord, ...]) -> DnsMessage:
        """This response with only ``answers`` (authority/additional dropped)."""
        return replace(self, answers=answers, authority=(), additional=())

    # ---- codec -------------------------------------------------------------------

    @classmethod
    def parse(cls, data: bytes) -> DnsMessage:
        try:
            return _Parser(data).message()
        except (struct.error, IndexError, UnicodeDecodeError) as exc:
            raise DnsFormatError(f"malformed DNS message: {exc}") from exc

    def encode(self) -> bytes:
        parts = [
            _HEADER.pack(
                self.id,
                self.flags,
                len(self.questions),
                len(self.answers),
                len(self.authority),
                len(self.additional),
            )
        ]
        for question in self.questions:
            parts.append(encode_name(question.name))
            parts.append(_QUESTION_FIXED.pack(question.qtype, question.qclass))
        for record in (*self.answers, *self.authority, *self.additional):
            parts.append(encode_name(record.name))
            parts.append(
                _RR_FIXED.pack(record.rtype, record.rclass, record.ttl, len(record.rdata))
            )
            parts.append(record.rdata)
        return b"".join(parts)


def encode_name(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if len(raw) > _MAX_LABEL:
            raise DnsFormatError(f"label too long: {label!r}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


class _Parser:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def message(self) -> DnsMessage:
        ident, flags, qd, an, ns, ar = self._unpack(_HEADER)
        questions = tuple(self._question() for _ in range(qd))
        answers = tuple(self._record() for _ in range(an))
        authority = tuple(self._record() for _ in range(ns))
        additional = tuple(self._record() for _ in range(ar))
        return DnsMessage(ident, flags, questions, answers, authority, additional)

    def _unpack(self, layout: struct.Struct) -> tuple[int, ...]:
        values = layout.unpack_from(self._data, self._offset)
        self._offset += layout.size
        return values

    def _question(self) -> Question:
        name = self._name()
        qtype, qclass = self._unpack(_QUESTION_FIXED)
        return Question(name, qtype, qclass)

    def _record(self) -> ResourceRecord:
        name = self._name()
        rtype, rclass, ttl, length = self._unpack(_RR_FIXED)
        start = self._offset
        end = start + length
        if end > len(self._data):
            raise DnsFormatError("record data runs past the message")
        rdata = self._decompressed_rdata(rtype, start, end)
        self._offset = end
        return ResourceRecord(name, rtype, rclass, ttl, rdata)

    def _decompressed_rdata(self, rtype: int, start: int, end: int) -> bytes:
        """RDATA with embedded names expanded, so it stays valid out of this message."""
        raw = self._data[start:end]
        if rtype in (RecordType.CNAME, RecordType.NS, RecordType.PTR):
            return encode_name(self._name_at(start)[0])
        if rtype == RecordType.MX:
            return raw[:2] + encode_name(self._name_at(start + 2)[0])
        if rtype == RecordType.SRV:
            return raw[:6] + encode_name(self._name_at(start + 6)[0])
        if rtype == RecordType.SOA:
            mname, offset = self._name_at(start)
            rname, offset = self._name_at(offset)
            return encode_name(mname) + encode_name(rname) + self._data[offset:end]
        return raw

    def _name(self) -> str:
        name, self._offset = self._name_at(self._offset)
        return name

    def _name_at(self, offset: int) -> tuple[str, int]:
        """The (decompressed) name at ``offset`` and the offset just after it."""
        labels: list[str] = []
        end: int | None = None
        for _ in range(_MAX_POINTER_JUMPS):
            length = self._data[offset]
            if length & _POINTER_MASK == _POINTER_MASK:
                pointer = ((length & ~_POINTER_MASK) << 8) | self._data[offset + 1]
                if end is None:
                    end = offset + 2
                offset = pointer
                continue
            if length & _POINTER_MASK:
                raise DnsFormatError("unsupported label type")
            if length == 0:
                return ".".join(labels), end if end is not None else offset + 1
            label = self._data[offset + 1 : offset + 1 + length]
            if len(label) != length:
                raise DnsFormatError("label runs past the message")
            labels.append(label.decode("ascii"))
            offset += 1 + length
        raise DnsFormatError("too many compression pointers")
