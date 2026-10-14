"""The network policy and its matcher: which rule decides a name or a connection.

Precedence (spec §3.3): the most specific matching rule wins; between an allow and a
deny of equal specificity the deny wins; no match falls to the default. Name rules and
address rules are separate families (the kernel only sees addresses, so names are
decided at DNS time):

* a **name** is decided by domain rules only;
* a **connection** is decided by address/host rules first, then by DNS pins, then
  protected ranges are refused, then the default applies (public addresses only).

This module is standard-library only: it also runs inside the gateway image.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise

from bulbi.errors import RuleError
from bulbi.gateway.protected import is_protected
from bulbi.gateway.rules import (
    ALL_PORTS,
    MAX_PORT,
    MIN_PORT,
    AddressLikeRule,
    AddressRule,
    DomainRule,
    HostRule,
    IPAddress,
    PortRange,
    Protocol,
    Rule,
    RuleParser,
)

HOST_NAME = "host.bulbi.internal"


class Action(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class Reason(StrEnum):
    ALLOWED_BY_RULE = "allowed_by_rule"
    DENIED_BY_RULE = "denied_by_rule"
    ALLOWED_BY_DEFAULT = "allowed_by_default"
    DENIED_BY_DEFAULT = "denied_by_default"
    ALLOWED_BY_DNS = "allowed_by_dns"
    DENIED_BY_DNS = "denied_by_dns"
    DENIED_PROTECTED = "denied_protected"
    DENIED_MALFORMED = "denied_malformed"


@dataclass(frozen=True)
class Decision:
    """The verdict for a name or a connection and what produced it."""

    action: Action
    reason: Reason
    rule: Rule | None = None

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW


@dataclass(frozen=True)
class PortSegment:
    """A contiguous port range of one protocol with a single decision."""

    protocol: Protocol
    ports: PortRange
    decision: Decision


@dataclass(frozen=True)
class NameCoverage:
    """How every (protocol, port) of a name is decided."""

    name: str
    segments: tuple[PortSegment, ...]

    @property
    def resolvable(self) -> bool:
        """A name resolves when at least one port of it is allowed."""
        return any(segment.decision.allowed for segment in self.segments)

    @property
    def decision(self) -> Decision:
        """Representative decision for logging the DNS query itself."""
        relevant = [s for s in self.segments if s.decision.allowed == self.resolvable]
        by_rule = [s for s in relevant if s.decision.rule is not None]
        return (by_rule or relevant)[0].decision

    def segments_where(self, action: Action, reason: Reason) -> list[PortSegment]:
        return [
            s for s in self.segments if s.decision.action is action and s.decision.reason is reason
        ]


@dataclass(frozen=True)
class NetworkPolicy:
    """``[network]`` parsed: default plus allow and deny rules."""

    default: Action
    allow: tuple[Rule, ...] = ()
    deny: tuple[Rule, ...] = ()

    @classmethod
    def parse(cls, default: str, allow: Iterable[str], deny: Iterable[str] = ()) -> NetworkPolicy:
        """Parse rule strings; raises :class:`RuleError` listing every malformed rule."""
        parser = RuleParser()
        parsed: dict[str, list[Rule]] = {"allow": [], "deny": []}
        errors: list[str] = []
        for section, texts in (("allow", allow), ("deny", deny)):
            for text in texts:
                try:
                    parsed[section].append(parser.parse(text))
                except RuleError as exc:
                    errors.append(str(exc))
        if errors:
            raise RuleError("; ".join(errors))
        return cls(Action(default), tuple(parsed["allow"]), tuple(parsed["deny"]))

    @property
    def rules(self) -> tuple[tuple[Action, Rule], ...]:
        return tuple(
            [(Action.ALLOW, rule) for rule in self.allow]
            + [(Action.DENY, rule) for rule in self.deny]
        )

    def rules_of(self, family: type[Rule] | tuple[type[Rule], ...]) -> list[tuple[Action, Rule]]:
        return [(action, rule) for action, rule in self.rules if isinstance(rule, family)]

    @property
    def has_host_rules(self) -> bool:
        return any(isinstance(rule, HostRule) for rule in self.allow)

    def rule_id(self, rule: Rule) -> int:
        """Stable index of a rule in :attr:`rules`, used to tag firewall log entries."""
        return next(i for i, (_, candidate) in enumerate(self.rules) if candidate is rule)


@dataclass
class PolicyMatcher:
    """Applies a :class:`NetworkPolicy` to names and connections."""

    policy: NetworkPolicy
    host_addresses: frozenset[IPAddress] = field(default_factory=frozenset)

    # ---- names (DNS) -------------------------------------------------------

    def decide_name(self, name: str, port: int, protocol: Protocol) -> Decision:
        """Decision for connecting to ``name`` on ``port``/``protocol``."""
        candidates = [
            (action, rule)
            for action, rule in self.policy.rules_of(DomainRule)
            if isinstance(rule, DomainRule)
            and rule.matches_name(name)
            and rule.applies_to(port, protocol)
        ]
        return self._most_specific(candidates) or self._default()

    def name_coverage(self, name: str) -> NameCoverage:
        """Every (protocol, port range) of ``name`` with its decision, merged."""
        name = name.lower().rstrip(".")
        if name == HOST_NAME:
            return self._host_name_coverage()
        matching = [
            rule
            for _, rule in self.policy.rules_of(DomainRule)
            if isinstance(rule, DomainRule) and rule.matches_name(name)
        ]
        segments: list[PortSegment] = []
        for protocol in Protocol:
            segments.extend(self._segments(name, protocol, matching))
        return NameCoverage(name, tuple(segments))

    def _segments(self, name: str, protocol: Protocol, rules: Sequence[Rule]) -> list[PortSegment]:
        bounds = {MIN_PORT, MAX_PORT + 1}
        for rule in rules:
            for port_range in rule.ports.effective_ranges():
                bounds.update({port_range.low, port_range.high + 1})
        edges = sorted(bounds)
        segments: list[PortSegment] = []
        for low, next_low in pairwise(edges):
            decision = self.decide_name(name, low, protocol)
            previous = segments[-1] if segments else None
            if previous is not None and previous.decision == decision:
                segments[-1] = PortSegment(
                    protocol, PortRange(previous.ports.low, next_low - 1), decision
                )
            else:
                segments.append(PortSegment(protocol, PortRange(low, next_low - 1), decision))
        return segments

    def _host_name_coverage(self) -> NameCoverage:
        """``host.bulbi.internal`` resolves only when a ``host`` rule allows something."""
        if self.policy.has_host_rules:
            decision = Decision(Action.ALLOW, Reason.ALLOWED_BY_RULE, self._first_host_rule())
        else:
            decision = Decision(Action.DENY, Reason.DENIED_BY_DEFAULT)
        return NameCoverage(
            HOST_NAME, tuple(PortSegment(p, ALL_PORTS, decision) for p in Protocol)
        )

    def _first_host_rule(self) -> Rule:
        return next(rule for rule in self.policy.allow if isinstance(rule, HostRule))

    # ---- connections (kernel) ----------------------------------------------

    def decide_connection(
        self,
        address: IPAddress,
        port: int,
        protocol: Protocol,
        dns_decision: Action | None = None,
    ) -> Decision:
        """Decision for a connection, mirroring the order of the nftables ruleset.

        ``dns_decision`` is what DNS pinning says about the address: ``ALLOW`` if a name
        allowed by a rule resolved to it, ``DENY`` if a denied name did (blacklist
        mode), ``None`` otherwise.
        """
        explicit = self.decide_by_address_rules(address, port, protocol)
        if explicit is not None:
            return explicit
        if dns_decision is Action.ALLOW:
            return Decision(Action.ALLOW, Reason.ALLOWED_BY_DNS)
        if dns_decision is Action.DENY:
            return Decision(Action.DENY, Reason.DENIED_BY_DNS)
        if is_protected(address):
            return Decision(Action.DENY, Reason.DENIED_PROTECTED)
        return self._default()

    def decide_by_address_rules(
        self, address: IPAddress, port: int, protocol: Protocol
    ) -> Decision | None:
        candidates = [
            (action, rule)
            for action, rule in self.policy.rules_of((AddressRule, HostRule))
            if self._address_rule(rule).matches_address(address, self.host_addresses)
            and rule.applies_to(port, protocol)
        ]
        return self._most_specific(candidates)

    def address_allowed_by_rule(self, address: IPAddress) -> bool:
        """Whether some address/host allow rule reaches ``address`` on any port.

        Used to decide whether a protected address may stay in a DNS answer.
        """
        return any(
            self._address_rule(rule).matches_address(address, self.host_addresses)
            for action, rule in self.policy.rules_of((AddressRule, HostRule))
            if action is Action.ALLOW
        )

    # ---- shared ------------------------------------------------------------

    @staticmethod
    def _address_rule(rule: Rule) -> AddressLikeRule:
        assert isinstance(rule, AddressRule | HostRule)
        return rule

    @staticmethod
    def _most_specific(candidates: Sequence[tuple[Action, Rule]]) -> Decision | None:
        if not candidates:
            return None
        # Highest specificity first; at equal specificity DENY sorts before ALLOW.
        action, rule = max(
            candidates, key=lambda item: (item[1].specificity(), item[0] is Action.DENY)
        )
        reason = Reason.ALLOWED_BY_RULE if action is Action.ALLOW else Reason.DENIED_BY_RULE
        return Decision(action, reason, rule)

    def _default(self) -> Decision:
        if self.policy.default is Action.ALLOW:
            return Decision(Action.ALLOW, Reason.ALLOWED_BY_DEFAULT)
        return Decision(Action.DENY, Reason.DENIED_BY_DEFAULT)
