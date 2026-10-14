"""Tests for the gateway's pure parts: rule parsing, matching, protected ranges."""

import ipaddress
import json
import os
import socket
import struct
import threading
from pathlib import Path

import pytest

from bulbi.errors import AuditLogError, RuleError
from bulbi.gateway.audit import AuditLogReader, AuditLogWriter, LogEntry
from bulbi.gateway.dns import (
    DnsFormatError,
    DnsMessage,
    Question,
    RecordType,
    ResourceRecord,
    ResponseCode,
    encode_name,
)
from bulbi.gateway.firewall import AddressEntry, FirewallContext, LogTag, NftablesBackend, PinKind
from bulbi.gateway.nflog import ConnectionAttempt, bind_messages, parse_datagram
from bulbi.gateway.policy import (
    HOST_NAME,
    Action,
    NetworkPolicy,
    PolicyMatcher,
    Reason,
)
from bulbi.gateway.protected import is_protected, overlaps_protected
from bulbi.gateway.relay import HostRelay
from bulbi.gateway.resolver import (
    DnsServer,
    Resolver,
    ResolverSink,
    Upstream,
    UpstreamError,
    address_entries,
    read_tcp_message,
)
from bulbi.gateway.rules import (
    ALL_PROTOCOLS,
    AddressRule,
    DomainRule,
    HostRule,
    PortRange,
    Protocol,
    RuleParser,
)
from bulbi.gateway.supervisor import PipeSink, Supervisor

TCP, UDP = Protocol.TCP, Protocol.UDP
ip = ipaddress.ip_address


def parse(text: str):
    return RuleParser().parse(text)


def matcher(default="deny", allow=(), deny=(), host=()) -> PolicyMatcher:
    policy = NetworkPolicy.parse(default, allow, deny)
    return PolicyMatcher(policy, frozenset(ip(a) for a in host))


# ---- Rule parsing ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "kind", "target", "ports", "protocols"),
    [
        ("pypi.org", DomainRule, "pypi.org", (), ALL_PROTOCOLS),
        ("PyPI.org.", DomainRule, "pypi.org", (), ALL_PROTOCOLS),
        ("*.github.com", DomainRule, "*.github.com", (), ALL_PROTOCOLS),
        ("broker.cloudamqp.com:5671", DomainRule, "broker.cloudamqp.com", ((5671, 5671),), None),
        ("host", HostRule, "host", (), ALL_PROTOCOLS),
        ("host:5432", HostRule, "host", ((5432, 5432),), None),
        ("host:15672,5672", HostRule, "host", ((5672, 5672), (15672, 15672)), None),
        ("192.168.1.20:6379", AddressRule, "192.168.1.20/32", ((6379, 6379),), None),
        ("10.20.0.0/16", AddressRule, "10.20.0.0/16", (), ALL_PROTOCOLS),
        ("203.0.113.0/24:25", AddressRule, "203.0.113.0/24", ((25, 25),), None),
        ("1.1.1.1:53/udp", AddressRule, "1.1.1.1/32", ((53, 53),), frozenset({UDP})),
        ("pypi.org/TCP", DomainRule, "pypi.org", (), frozenset({TCP})),
        (
            "example.com:8000-8100,9000",
            DomainRule,
            "example.com",
            ((8000, 8100), (9000, 9000)),
            None,
        ),
        ("2001:db8::1", AddressRule, "2001:db8::1/128", (), ALL_PROTOCOLS),
        ("2001:db8::/32", AddressRule, "2001:db8::/32", (), ALL_PROTOCOLS),
        ("[2001:db8::1]:443/tcp", AddressRule, "2001:db8::1/128", ((443, 443),), frozenset({TCP})),
        ("[::ffff:10.0.0.1]", AddressRule, "10.0.0.1/32", (), ALL_PROTOCOLS),
    ],
)
def test_rule_parsing(text, kind, target, ports, protocols):
    rule = parse(text)
    assert isinstance(rule, kind)
    assert rule.target_text() == target
    assert [(r.low, r.high) for r in rule.ports.ranges] == list(ports)
    assert rule.protocols == (protocols or ALL_PROTOCOLS)
    assert str(rule) == text


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "[::1",
        "[::1]x",
        "[::1]:",
        "pypi.org:",
        "pypi.org:http",
        "pypi.org:0",
        "pypi.org:70000",
        "pypi.org:90-80",
        "*",
        "*.",
        "a.*.b",
        "bad_label-.com",
        "exa mple.com",
        "10.0.0.1/8",
        "999.1.1.1",
        "/tcp",
        "host:",
        "a..b",
    ],
)
def test_malformed_rules_raise_rule_error_not_tracebacks(text):
    with pytest.raises(RuleError):
        parse(text)


def test_non_string_rule_is_a_rule_error():
    with pytest.raises(RuleError, match="must be a string"):
        RuleParser().parse(42)  # type: ignore[arg-type]


def test_policy_parse_reports_every_malformed_rule():
    with pytest.raises(RuleError) as excinfo:
        NetworkPolicy.parse("deny", ["ok.com", "[::1"], ["bad:port"])
    assert "[::1" in str(excinfo.value)
    assert "bad:port" in str(excinfo.value)


def test_rules_are_equal_regardless_of_spelling():
    assert parse("PyPI.org:443,80") == parse("pypi.org:80,443")
    assert parse("pypi.org") != parse("pypi.org:443")
    assert parse("pypi.org/tcp") != parse("pypi.org")


# ---- Matcher: names ----------------------------------------------------------------


def test_exact_domain_matches_only_itself():
    m = matcher(allow=["pypi.org"])
    assert m.decide_name("pypi.org", 443, TCP).allowed
    assert not m.decide_name("files.pypi.org", 443, TCP).allowed


def test_wildcard_matches_subdomains_not_apex():
    m = matcher(allow=["*.github.com"])
    assert m.decide_name("api.github.com", 443, TCP).allowed
    assert m.decide_name("a.b.github.com", 22, TCP).allowed
    assert not m.decide_name("github.com", 443, TCP).allowed
    assert not m.decide_name("evilgithub.com", 443, TCP).allowed


def test_exact_beats_wildcard():
    m = matcher(allow=["*.github.com"], deny=["gist.github.com"])
    decision = m.decide_name("gist.github.com", 443, TCP)
    assert (decision.action, decision.reason, str(decision.rule)) == (
        Action.DENY,
        Reason.DENIED_BY_RULE,
        "gist.github.com",
    )
    assert m.decide_name("api.github.com", 443, TCP).allowed


def test_longer_wildcard_beats_shorter():
    m = matcher(allow=["*.example.com"], deny=["*.internal.example.com"])
    assert not m.decide_name("db.internal.example.com", 5432, TCP).allowed
    assert m.decide_name("www.example.com", 443, TCP).allowed
    m = matcher(deny=["*.example.com"], allow=["*.cdn.example.com"])
    assert m.decide_name("img.cdn.example.com", 443, TCP).allowed


def test_rule_with_port_beats_same_rule_without():
    m = matcher(allow=["example.com"], deny=["example.com:25"])
    assert m.decide_name("example.com", 443, TCP).allowed
    assert not m.decide_name("example.com", 25, TCP).allowed


def test_deny_wins_ties():
    m = matcher(allow=["example.com"], deny=["example.com"])
    assert m.decide_name("example.com", 443, TCP).reason is Reason.DENIED_BY_RULE


def test_proto_suffix_restricts_rule():
    m = matcher(allow=["dns.example:53/udp"])
    assert m.decide_name("dns.example", 53, UDP).allowed
    assert not m.decide_name("dns.example", 53, TCP).allowed


@pytest.mark.parametrize(("default", "allowed"), [("deny", False), ("allow", True)])
def test_unmatched_names_fall_to_default(default, allowed):
    decision = matcher(default).decide_name("anything.test", 443, TCP)
    assert decision.allowed is allowed
    assert decision.reason in {Reason.ALLOWED_BY_DEFAULT, Reason.DENIED_BY_DEFAULT}
    assert decision.rule is None


def test_name_coverage_segments():
    m = matcher(allow=["example.com"], deny=["example.com:25"])
    coverage = m.name_coverage("Example.COM.")
    assert coverage.resolvable
    tcp = [
        (s.ports.low, s.ports.high, s.decision.action)
        for s in coverage.segments
        if s.protocol is TCP
    ]
    assert tcp == [(0, 24, Action.ALLOW), (25, 25, Action.DENY), (26, 65535, Action.ALLOW)]


def test_denied_name_is_not_resolvable():
    m = matcher(allow=["*.github.com"], deny=["gist.github.com"])
    coverage = m.name_coverage("gist.github.com")
    assert not coverage.resolvable
    assert str(coverage.decision.rule) == "gist.github.com"


def test_port_limited_allow_resolves_with_only_those_ports():
    coverage = matcher(allow=["broker.cloudamqp.com:5671"]).name_coverage("broker.cloudamqp.com")
    allowed = [s for s in coverage.segments if s.decision.allowed]
    assert [(s.protocol, str(s.ports)) for s in allowed] == [(TCP, "5671"), (UDP, "5671")]


def test_host_name_resolves_only_with_host_rule():
    assert matcher(allow=["host:5432"]).name_coverage(HOST_NAME).resolvable
    assert not matcher(allow=["pypi.org"]).name_coverage(HOST_NAME).resolvable
    assert not matcher("allow").name_coverage(HOST_NAME).resolvable


# ---- Matcher: connections ----------------------------------------------------------


def test_longer_prefix_wins():
    m = matcher(allow=["10.20.0.0/16"], deny=["10.20.5.0/24"])
    assert m.decide_connection(ip("10.20.1.1"), 80, TCP).allowed
    assert not m.decide_connection(ip("10.20.5.9"), 80, TCP).allowed


def test_address_rule_with_port():
    m = matcher(allow=["192.168.1.20:6379"])
    assert m.decide_connection(ip("192.168.1.20"), 6379, TCP).allowed
    decision = m.decide_connection(ip("192.168.1.20"), 22, TCP)
    assert decision.reason is Reason.DENIED_PROTECTED


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.1.2.3", "172.17.0.1", "192.168.65.254", "169.254.169.254", "100.64.0.1",
     "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "224.0.0.1"],
)  # fmt: skip
def test_protected_addresses_are_denied_even_in_allow_mode(address):
    decision = matcher("allow").decide_connection(ip(address), 443, TCP)
    assert decision.reason is Reason.DENIED_PROTECTED


def test_protected_address_reachable_only_through_address_rule():
    m = matcher("allow", allow=["10.0.0.5:5432"])
    assert m.decide_connection(ip("10.0.0.5"), 5432, TCP).allowed
    assert not m.decide_connection(ip("10.0.0.5"), 5433, TCP).allowed


def test_allowed_domain_never_unlocks_protected_address():
    m = matcher(allow=["localtest.me"])
    # The resolver strips protected answers, so nothing is pinned; without a pin it is denied.
    assert not m.address_allowed_by_rule(ip("127.0.0.1"))
    assert not m.decide_connection(ip("127.0.0.1"), 80, TCP).allowed


def test_host_rule_matches_host_addresses():
    m = matcher(allow=["host:5432"], host=["192.168.65.254"])
    assert m.decide_connection(ip("192.168.65.254"), 5432, TCP).allowed
    assert not m.decide_connection(ip("192.168.65.254"), 22, TCP).allowed
    assert m.address_allowed_by_rule(ip("192.168.65.254"))


def test_ipv4_mapped_address_matches_ipv4_rule():
    m = matcher(allow=["10.20.0.0/16"])
    assert m.decide_connection(ip("::ffff:10.20.1.1"), 80, TCP).allowed


def test_public_addresses_follow_default_and_dns_pins():
    deny_mode = matcher()
    assert not deny_mode.decide_connection(ip("1.1.1.1"), 443, TCP).allowed
    assert deny_mode.decide_connection(ip("1.1.1.1"), 443, TCP, Action.ALLOW).allowed
    allow_mode = matcher("allow", deny=["example.com"])
    assert allow_mode.decide_connection(ip("1.1.1.1"), 443, TCP).allowed
    assert not allow_mode.decide_connection(ip("1.1.1.1"), 443, TCP, Action.DENY).allowed


def test_address_deny_beats_dns_pin():
    m = matcher(allow=["pypi.org"], deny=["151.101.0.0/16"])
    decision = m.decide_connection(ip("151.101.1.1"), 443, TCP, Action.ALLOW)
    assert decision.reason is Reason.DENIED_BY_RULE


# ---- Protected ranges --------------------------------------------------------------


def test_public_addresses_are_not_protected():
    for address in ("1.1.1.1", "151.101.0.223", "2606:4700::1111", "::ffff:8.8.8.8"):
        assert not is_protected(ip(address))


def test_overlaps_protected():
    assert overlaps_protected(ipaddress.ip_network("10.0.0.0/8"))
    assert overlaps_protected(ipaddress.ip_network("0.0.0.0/0"))
    assert not overlaps_protected(ipaddress.ip_network("8.8.8.0/24"))


def test_port_range_contains():
    assert 5 in PortRange(1, 10)
    assert "5" not in PortRange(1, 10)


# ---- Firewall rendering (golden files) -----------------------------------------------

GOLDEN = Path(__file__).parent / "golden"
GOLDEN_CASES = {
    "whitelist": (
        "deny",
        ["pypi.org", "*.github.com", "host:5432", "1.1.1.1:53/udp", "10.20.0.0/16",
         "[2001:db8::1]:443/tcp"],
        ["gist.github.com", "10.20.5.0/24"],
    ),
    "blacklist": ("allow", [], ["example.com", "*.telemetry.example", "203.0.113.0/24:25"]),
    "mixed": (
        "deny",
        ["broker.cloudamqp.com:5671", "host:15672,5672", "192.168.1.20:6379", "8.8.8.0/24:53,853"],
        ["8.8.8.8:853"],
    ),
}  # fmt: skip
CONTEXT = FirewallContext(resolver_uid=999, host_addresses=(ip("192.168.65.254"),))


@pytest.mark.parametrize("case", sorted(GOLDEN_CASES))
def test_nftables_ruleset_matches_golden_file(case):
    default, allow, deny = GOLDEN_CASES[case]
    rendered = NftablesBackend().render(NetworkPolicy.parse(default, allow, deny), CONTEXT)
    assert rendered == (GOLDEN / f"{case}.nft").read_text()


def test_address_rules_are_ordered_like_the_matcher():
    rendered = NftablesBackend().render(
        NetworkPolicy.parse("deny", ["10.20.0.0/16"], ["10.20.5.0/24"]), CONTEXT
    )
    assert rendered.index("10.20.5.0/24") < rendered.index("10.20.0.0/16")


def test_host_rule_without_known_host_address_is_inactive():
    context = FirewallContext(resolver_uid=999)
    rendered = NftablesBackend().render(NetworkPolicy.parse("deny", ["host:5432"]), context)
    assert "# 'host:5432': no host address known, rule inactive" in rendered
    assert "dport { 5432 }" not in rendered


def test_render_entries_adds_pins_with_minimum_timeout():
    coverage = matcher(allow=["broker.example:5671/tcp"]).name_coverage("broker.example")
    segments = tuple(s for s in coverage.segments if s.decision.allowed)
    script = NftablesBackend().render_entries(
        [
            AddressEntry(ip("3.3.3.3"), segments, ttl=30),
            AddressEntry(ip("2606:4700::1"), segments, ttl=900),
            AddressEntry(ip("4.4.4.4"), segments, ttl=60, kind=PinKind.DENY),
        ]
    )
    assert script.splitlines() == [
        "add element inet bulbi pin4 { 3.3.3.3 . tcp . 5671 timeout 300s }",
        "add element inet bulbi pin6 { 2606:4700::1 . tcp . 5671 timeout 900s }",
        "add element inet bulbi block4 { 4.4.4.4 . tcp . 5671 timeout 300s }",
    ]


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "bulbi",
        "bulbi|allow|nope|-",
        "bulbi|maybe|allowed_by_rule|1",
        "x|allow|allowed_by_rule|1",
        "bulbi|allow|allowed_by_rule|one",
        "bulbi|allow|allowed_by_rule|1|extra",
    ],
)
def test_log_tag_decode_rejects_garbage(prefix):
    assert LogTag.decode(prefix) is None


def test_log_tag_round_trip():
    tag = LogTag(Action.DENY, Reason.DENIED_BY_RULE, 7)
    assert LogTag.decode(tag.encode() + "\0") == tag


# ---- DNS codec ---------------------------------------------------------------------


def _query(name: str, qtype: int = RecordType.A, ident: int = 0x1234) -> bytes:
    return DnsMessage(ident, 0x0100, (Question(name, qtype),)).encode()


def _response(query: bytes, *records: ResourceRecord) -> bytes:
    return DnsMessage.parse(query).reply(ResponseCode.NOERROR, records).encode()


def test_dns_round_trip():
    query = _query("PyPI.org")
    message = DnsMessage.parse(query)
    assert (message.id, message.questions[0].name, message.is_response) == (
        0x1234,
        "PyPI.org",
        False,
    )
    assert DnsMessage.parse(message.encode()) == message


def test_dns_parses_compressed_names_and_cname_rdata():
    # Hand-built response: question pypi.org A; answer "pypi.org CNAME cdn.pypi.org" and
    # "cdn.pypi.org A 151.101.0.223", both using compression pointers.
    header = bytes.fromhex("abcd 8180 0001 0002 0000 0000")
    question = b"\x04pypi\x03org\x00" + b"\x00\x01\x00\x01"  # name at offset 12
    cname = (
        b"\xc0\x0c" + b"\x00\x05\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x06" + b"\x03cdn\xc0\x0c"
    )
    cname_target = 12 + len(question) + 12  # offset of "\x03cdn" inside the CNAME RDATA
    a_record = (
        bytes([0xC0, cname_target]) + b"\x00\x01\x00\x01" + b"\x00\x00\x01\x2c" + b"\x00\x04"
        + bytes([151, 101, 0, 223])
    )  # fmt: skip
    message = DnsMessage.parse(header + question + cname + a_record)
    assert [r.name for r in message.answers] == ["pypi.org", "cdn.pypi.org"]
    assert message.answers[0].rdata == encode_name("cdn.pypi.org")
    assert message.answers[1].address == ip("151.101.0.223")
    assert DnsMessage.parse(message.encode()).answers == message.answers


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00" * 5,
        bytes.fromhex("0001 0100 0001 0000 0000 0000") + b"\x05ab",
        bytes.fromhex("0001 0100 0001 0000 0000 0000") + b"\xc0\x0c",
        bytes.fromhex("0001 8180 0000 0001 0000 0000")
        + b"\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x10ab",
    ],
)
def test_malformed_dns_raises_format_error(data):
    with pytest.raises(DnsFormatError):
        DnsMessage.parse(data)


# ---- Resolver ----------------------------------------------------------------------


class FakeUpstream(Upstream):
    def __init__(self, answers: dict[str, list[str]] | None = None, fail: bool = False) -> None:
        self.answers = answers or {}
        self.queries: list[str] = []
        self.fail = fail

    def query(self, payload: bytes) -> bytes:
        name = DnsMessage.parse(payload).questions[0].name.lower()
        self.queries.append(name)
        if self.fail:
            raise UpstreamError("timeout")
        records = [
            ResourceRecord.for_address(name, ip(a), 120) for a in self.answers.get(name, [])
        ]
        return _response(payload, *records)


class RecordingSink(ResolverSink):
    def __init__(self) -> None:
        self.learned_records: list[tuple[str, list[tuple[object, int]]]] = []
        self.entries: list[LogEntry] = []

    def learned(self, name, records):
        self.learned_records.append((name, records))

    def audit(self, entry):
        self.entries.append(entry)


def _resolver(m: PolicyMatcher, upstream: Upstream) -> tuple[Resolver, RecordingSink]:
    sink = RecordingSink()
    return Resolver(m, upstream, sink, clock=lambda: "T"), sink


def test_denied_name_never_reaches_upstream():
    upstream = FakeUpstream({"gist.github.com": ["140.82.112.4"]})
    resolver, sink = _resolver(matcher(allow=["*.github.com"], deny=["gist.github.com"]), upstream)
    response = DnsMessage.parse(resolver.answer(_query("gist.github.com"), UDP))
    assert response.rcode == ResponseCode.NXDOMAIN
    assert upstream.queries == []
    (entry,) = sink.entries
    assert (entry.domain, entry.action, entry.method, entry.reason, entry.rule, entry.proto) == (
        "gist.github.com", "deny", "DNS", "denied_by_rule", "gist.github.com", "udp",
    )  # fmt: skip


def test_unlisted_name_in_whitelist_is_nxdomain_without_upstream():
    upstream = FakeUpstream()
    resolver, sink = _resolver(matcher(allow=["pypi.org"]), upstream)
    response = DnsMessage.parse(resolver.answer(_query("example.com"), UDP))
    assert response.rcode == ResponseCode.NXDOMAIN
    assert upstream.queries == []
    assert sink.entries[0].reason == "denied_by_default"


def test_allowed_name_answer_is_vetted_and_learned():
    upstream = FakeUpstream({"localtest.me": ["127.0.0.1", "8.8.4.4", "10.0.0.7"]})
    m = matcher(allow=["localtest.me", "10.0.0.7:22"])
    resolver, sink = _resolver(m, upstream)
    response = DnsMessage.parse(resolver.answer(_query("localtest.me", ident=7), TCP))
    assert response.id == 7
    assert [r.address for r in response.answers] == [ip("8.8.4.4"), ip("10.0.0.7")]
    assert sink.learned_records == [
        ("localtest.me", [(ip("8.8.4.4"), 120), (ip("10.0.0.7"), 120)])
    ]
    assert sink.entries[0].ip == "8.8.4.4,10.0.0.7"
    assert sink.entries[0].action == "allow"


def test_name_resolving_only_to_protected_addresses_gets_empty_answer():
    upstream = FakeUpstream({"localtest.me": ["127.0.0.1"]})
    resolver, sink = _resolver(matcher(allow=["localtest.me"]), upstream)
    response = DnsMessage.parse(resolver.answer(_query("localtest.me"), UDP))
    assert response.rcode == ResponseCode.NOERROR
    assert response.answers == ()
    assert sink.learned_records == [("localtest.me", [])]


def test_upstream_failure_is_servfail():
    resolver, _ = _resolver(matcher(allow=["pypi.org"]), FakeUpstream(fail=True))
    response = DnsMessage.parse(resolver.answer(_query("pypi.org"), UDP))
    assert response.rcode == ResponseCode.SERVFAIL


def test_host_name_is_answered_locally():
    upstream = FakeUpstream()
    m = matcher(allow=["host:5432"], host=["192.168.65.254"])
    resolver, _ = _resolver(m, upstream)
    response = DnsMessage.parse(resolver.answer(_query(HOST_NAME), UDP))
    assert [r.address for r in response.answers] == [ip("192.168.65.254")]
    aaaa = DnsMessage.parse(resolver.answer(_query(HOST_NAME, RecordType.AAAA), UDP))
    assert aaaa.answers == ()
    assert upstream.queries == []


@pytest.mark.parametrize("query", [b"", b"garbage", b"\x00\x01" * 3])
def test_malformed_query_is_dropped_and_logged_not_raised(query):
    resolver, sink = _resolver(matcher(allow=["pypi.org"]), FakeUpstream())
    assert resolver.answer(query, UDP) is None
    assert (sink.entries[0].domain, sink.entries[0].reason) == ("(malformed)", "denied_malformed")


def test_response_or_multi_question_query_is_formerr():
    resolver, _ = _resolver(matcher(allow=["pypi.org"]), FakeUpstream())
    two = DnsMessage(1, 0x0100, (Question("a.b", 1), Question("c.d", 1))).encode()
    assert DnsMessage.parse(resolver.answer(two, UDP)).rcode == ResponseCode.FORMERR


def test_address_entries_pin_allowed_and_block_denied_in_blacklist_mode():
    whitelist = matcher(allow=["example.com"], deny=["example.com:25"])
    entries = address_entries(whitelist, whitelist.name_coverage("example.com"), ip("9.9.9.9"), 60)
    assert [e.kind for e in entries] == [PinKind.ALLOW]
    assert all(s.decision.allowed for s in entries[0].segments)

    blacklist = matcher("allow", deny=["example.com:25"])
    entries = address_entries(blacklist, blacklist.name_coverage("example.com"), ip("9.9.9.9"), 60)
    assert [e.kind for e in entries] == [PinKind.DENY]
    assert [str(s.ports) for s in entries[0].segments] == ["25", "25"]


def test_dns_server_answers_over_udp_and_tcp():
    resolver, _ = _resolver(
        matcher(allow=["pypi.org"]), FakeUpstream({"pypi.org": ["151.101.0.223"]})
    )
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    tcp = socket.create_server(("127.0.0.1", 0))
    threading.Thread(target=DnsServer(resolver, udp, tcp).serve_forever, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(_query("pypi.org"), udp.getsockname())
        assert DnsMessage.parse(client.recv(4096)).answers[0].address == ip("151.101.0.223")
    with socket.create_connection(tcp.getsockname(), timeout=5) as client:
        query = _query("pypi.org")
        client.sendall(len(query).to_bytes(2, "big") + query)
        assert DnsMessage.parse(read_tcp_message(client)).rcode == ResponseCode.NOERROR


# ---- NFLOG parsing -------------------------------------------------------------------


def _nflog_datagram(prefix: str, packet: bytes) -> bytes:
    def attr(kind: int, payload: bytes) -> bytes:
        length = 4 + len(payload)
        return struct.pack("=HH", length, kind) + payload + b"\0" * (-length % 4)

    body = struct.pack("=BBH", 2, 0, 0) + attr(10, prefix.encode() + b"\0") + attr(9, packet)
    return struct.pack("=IHHII", 16 + len(body), (4 << 8) | 0, 0, 0, 0) + body


def _ipv4_tcp(dst: str, port: int) -> bytes:
    header = (
        bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + ip("10.0.0.2").packed + ip(dst).packed
    )
    return header + struct.pack("!HH", 40000, port) + b"\0" * 16


def test_nflog_datagram_is_decoded():
    data = _nflog_datagram("bulbi|deny|denied_protected|-", _ipv4_tcp("169.254.169.254", 80))
    (attempt,) = list(parse_datagram(data))
    assert attempt.tag == LogTag(Action.DENY, Reason.DENIED_PROTECTED)
    assert (attempt.address, attempt.port, attempt.protocol) == (ip("169.254.169.254"), 80, TCP)


@pytest.mark.parametrize(
    "data",
    [b"", b"\xff" * 7, b"\xff" * 64, _nflog_datagram("other|x", _ipv4_tcp("1.1.1.1", 1)),
     _nflog_datagram("bulbi|allow|allowed_by_dns|-", b"\x45")],
)  # fmt: skip
def test_nflog_garbage_yields_nothing(data):
    assert list(parse_datagram(data)) == []


def test_nflog_bind_messages_are_well_formed():
    for message in bind_messages(1):
        assert struct.unpack_from("=I", message)[0] == len(message)
        assert struct.unpack_from("=H", message, 4)[0] == (4 << 8) | 1


# ---- Audit log -----------------------------------------------------------------------


def test_audit_entry_keeps_legacy_keys_and_adds_new_ones(tmp_path):
    log = tmp_path / ".bulbi" / "proxy.log"
    writer = AuditLogWriter(log)
    entry = LogEntry("T", "pypi.org", "allow", "TCP", "151.101.0.223:443",
                     "allowed_by_dns", None, "151.101.0.223", 443, "tcp")  # fmt: skip
    writer.write(entry)
    log.write_text(
        log.read_text()
        + '{"timestamp": "old", "domain": "a", "action": "deny", "method": "GET", "url": "u"}\n'
    )
    raw = json.loads(log.read_text().splitlines()[0])
    assert list(raw) == [
        "timestamp",
        "domain",
        "action",
        "method",
        "url",
        "reason",
        "rule",
        "ip",
        "port",
        "proto",
    ]
    entries = AuditLogReader(log).entries()
    assert entries[0] == entry
    assert (entries[1].method, entries[1].reason, entries[1].port) == ("GET", None, None)


def test_audit_reader_rejects_malformed_lines(tmp_path):
    log = tmp_path / "proxy.log"
    log.write_text('{"action": "deny"}\n\nnot json\n')
    with pytest.raises(AuditLogError, match="line 3"):
        AuditLogReader(log).entries()


# ---- Host relay ----------------------------------------------------------------------


@pytest.fixture
def echo_port():
    server = socket.create_server(("::1", 0), family=socket.AF_INET6)
    port = server.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(conn.recv(1024))

    threading.Thread(target=serve, daemon=True).start()
    yield port
    server.close()


def _relay(port: int) -> HostRelay:
    relay = HostRelay("127.0.0.1", [port], target_host="::1")
    relay.start()
    return relay


def test_relay_forwards_from_allowed_source(echo_port):
    relay = _relay(echo_port)
    relay.allow_source("127.0.0.1")
    try:
        with socket.create_connection(("127.0.0.1", echo_port), timeout=5) as client:
            client.sendall(b"ping")
            assert client.recv(16) == b"ping"
    finally:
        relay.stop()


def test_relay_refuses_other_sources(echo_port):
    relay = _relay(echo_port)
    relay.allow_source("172.30.0.2")
    try:
        with socket.create_connection(("127.0.0.1", echo_port), timeout=5) as client:
            client.sendall(b"ping")
            try:
                received = client.recv(16)
            except ConnectionResetError:
                received = b""
            assert received == b""
    finally:
        relay.stop()


def test_relay_listens_only_on_declared_ports(echo_port):
    relay = _relay(echo_port)
    try:
        assert relay.ports == [echo_port]
        with socket.create_server(("127.0.0.1", 0)) as spare:
            free_port = spare.getsockname()[1]
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", free_port), timeout=2)
    finally:
        relay.stop()


# ---- Supervisor / resolver pipe --------------------------------------------------------


class _RecordingLoader:
    def __init__(self) -> None:
        self.scripts: list[str] = []

    def load(self, script: str) -> None:
        self.scripts.append(script)


def _supervisor(m: PolicyMatcher, tmp_path: Path, loader=None) -> Supervisor:
    return Supervisor(
        m.policy,
        m,
        NftablesBackend(),
        loader or _RecordingLoader(),
        AuditLogWriter(tmp_path / "proxy.log"),
        clock=lambda: "T",
    )


def test_learned_answers_are_pinned_before_the_resolver_replies(tmp_path):
    """The DNS answer must not reach the box before its addresses are pinned."""
    m = matcher(allow=["pypi.org"])
    loader = _RecordingLoader()
    supervisor = _supervisor(m, tmp_path, loader)
    to_parent_r, to_parent_w = os.pipe()
    to_child_r, to_child_w = os.pipe()
    sink = PipeSink(os.fdopen(to_parent_w, "w"), os.fdopen(to_child_r))
    parent_in, parent_out = os.fdopen(to_parent_r), os.fdopen(to_child_w, "w")
    threading.Thread(target=supervisor.consume, args=(parent_in, parent_out), daemon=True).start()

    sink.learned("pypi.org", [(ip("151.101.0.223"), 60)])

    assert loader.scripts and "151.101.0.223 . tcp . 0-65535" in loader.scripts[0]


def test_learned_does_not_hang_when_the_supervisor_is_gone(tmp_path):
    to_parent_r, to_parent_w = os.pipe()
    to_child_r, to_child_w = os.pipe()
    os.close(to_child_w)  # the supervisor died
    sink = PipeSink(os.fdopen(to_parent_w, "w"), os.fdopen(to_child_r), ack_timeout=0.2)
    sink.learned("pypi.org", [(ip("151.101.0.223"), 60)])  # returns instead of blocking
    os.close(to_parent_r)


def test_supervisor_ignores_reports_for_denied_names_and_protected_addresses(tmp_path):
    m = matcher(allow=["pypi.org"])
    loader = _RecordingLoader()
    supervisor = _supervisor(m, tmp_path, loader)
    supervisor.learned("evil.test", [["1.2.3.4", 60]])
    supervisor.learned("pypi.org", [["127.0.0.1", 60]])
    assert all(not script.strip() for script in loader.scripts)


def test_supervisor_survives_malformed_messages(tmp_path):
    supervisor = _supervisor(matcher(allow=["pypi.org"]), tmp_path)
    for line in [
        "",
        "{",
        "[]",
        '{"kind": "learned"}',
        '{"kind": "learned", "name": "pypi.org", "records": [["nope", 1]]}',
    ]:
        supervisor.handle_message(line)


def test_connection_attempts_are_audited_with_name_and_rule(tmp_path):
    m = matcher(allow=["pypi.org", "10.0.0.0/24:5432"])
    supervisor = _supervisor(m, tmp_path)
    supervisor.learned("pypi.org", [["151.101.0.223", 60]])
    supervisor.record_attempt(
        ConnectionAttempt(
            LogTag(Action.ALLOW, Reason.ALLOWED_BY_DNS), ip("151.101.0.223"), 443, TCP
        )
    )
    supervisor.record_attempt(
        ConnectionAttempt(
            LogTag(Action.ALLOW, Reason.ALLOWED_BY_RULE, 1), ip("10.0.0.5"), 5432, TCP
        )
    )
    first, second = AuditLogReader(tmp_path / "proxy.log").entries()
    assert (first.domain, first.method, first.url, first.reason) == (
        "pypi.org",
        "TCP",
        "151.101.0.223:443",
        "allowed_by_dns",
    )
    assert (second.domain, second.rule, second.port) == ("10.0.0.5", "10.0.0.0/24:5432", 5432)
