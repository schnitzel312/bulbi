"""The effective network policy in plain words, for ``bulbi check``."""

from __future__ import annotations

from bulbi.errors import RuleError
from bulbi.gateway.policy import Action, NetworkPolicy
from bulbi.gateway.rules import DomainRule, Rule
from bulbi.spec import NetworkSpec

SHARED_IP_NOTE = (
    "Domain rules are enforced on the addresses a name resolves to; another site sharing "
    "a CDN address with an allowed domain is reachable too."
)
_LOCAL_NOTE = "Local/private blocked unless listed."


class PolicyDescriber:
    """Summarises a ``[network]`` section in one or two sentences."""

    def describe(self, network: NetworkSpec) -> str:
        try:
            policy = NetworkPolicy.parse(network.default, network.allow, network.deny)
        except RuleError:
            return "Invalid network rules (see errors below)."
        if policy.default is Action.ALLOW:
            return self._blacklist(policy)
        return self._whitelist(policy)

    def _whitelist(self, policy: NetworkPolicy) -> str:
        if not policy.allow:
            return f"Whitelist. Nothing is reachable. {_LOCAL_NOTE}"
        return (
            f"Whitelist. Any protocol to {self._targets(policy.allow)}."
            f"{self._deny_count(policy)} {_LOCAL_NOTE}"
        )

    def _blacklist(self, policy: NetworkPolicy) -> str:
        allowed = f" Also allowed: {self._targets(policy.allow)}." if policy.allow else ""
        excepted = (
            f" except {len(policy.deny)} {self._plural(len(policy.deny), 'rule')}"
            if policy.deny
            else ""
        )
        return (
            f"Blacklist (best effort). Any protocol to any public destination{excepted}."
            f"{allowed} {_LOCAL_NOTE}"
        )

    def _targets(self, rules: tuple[Rule, ...]) -> str:
        domains = [rule for rule in rules if isinstance(rule, DomainRule)]
        others = [str(rule) for rule in rules if not isinstance(rule, DomainRule)]
        parts = []
        if domains:
            parts.append(f"{len(domains)} {self._plural(len(domains), 'domain')}")
        parts.extend(others)
        return ", ".join(parts)

    def _deny_count(self, policy: NetworkPolicy) -> str:
        count = len(policy.deny)
        return f" Deny {count} {self._plural(count, 'rule')}." if count else ""

    @staticmethod
    def _plural(count: int, word: str) -> str:
        return word if count == 1 else f"{word}s"
