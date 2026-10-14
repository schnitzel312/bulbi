"""Tests for the gateway's pure parts: rule parsing, matching, protected ranges."""

import ipaddress

import pytest

from bulbi.errors import RuleError
from bulbi.gateway.policy import (
    HOST_NAME,
    Action,
    NetworkPolicy,
    PolicyMatcher,
    Reason,
)
from bulbi.gateway.protected import is_protected, overlaps_protected
from bulbi.gateway.rules import (
    ALL_PROTOCOLS,
    AddressRule,
    DomainRule,
    HostRule,
    PortRange,
    Protocol,
    RuleParser,
)

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
