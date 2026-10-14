"""Rules about the outbound network policy (``[network]``)."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.errors import RuleError
from bulbi.gateway.protected import overlaps_protected
from bulbi.gateway.rules import AddressRule, HostRule, Rule, RuleParser
from bulbi.spec import BulbiSpec, NetworkDefault
from bulbi.validation.base import ValidationIssue, ValidationRule

# Allow rules into protected ranges wider than this are flagged.
_NARROWEST_WIDE_PREFIX = {4: 24, 6: 64}


def _parsed(texts: list[str]) -> list[Rule]:
    """The rules that parse; malformed ones are reported by :class:`RuleSyntaxRule`."""
    parser = RuleParser()
    rules = []
    for text in texts:
        try:
            rules.append(parser.parse(text))
        except RuleError:
            continue
    return rules


class RuleSyntaxRule(ValidationRule):
    """Every allow and deny entry must be a well-formed rule."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        parser = RuleParser()
        for section, texts in (("allow", spec.network.allow), ("deny", spec.network.deny)):
            for text in texts:
                try:
                    parser.parse(text)
                except RuleError as exc:
                    yield ValidationIssue.error(f"network.{section}: {exc}")


class DenyEqualsAllowRule(ValidationRule):
    """A deny identical to an allow cancels it, which is almost certainly a mistake."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        allowed = set(_parsed(spec.network.allow))
        for rule in _parsed(spec.network.deny):
            if rule in allowed:
                yield ValidationIssue.error(
                    f"network rule '{rule}' is both allowed and denied (deny wins)"
                )


class OpenNetworkRule(ValidationRule):
    """Blacklist mode is best effort; say so."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.network.default is NetworkDefault.ALLOW:
            yield ValidationIssue.warning(
                "network.default is 'allow' — blacklist mode is best effort: a denied service "
                "can still be reached by raw IP or DNS-over-HTTPS. Consider 'deny' with an "
                "explicit allowlist"
            )


class AllowModeWithoutDenyRule(ValidationRule):
    """``default = "allow"`` with nothing denied lets the agent reach any public host."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.network.default is NetworkDefault.ALLOW and not spec.network.deny:
            yield ValidationIssue.warning(
                "network.default is 'allow' and network.deny is empty — "
                "every public destination is reachable"
            )


class EmptyAllowlistRule(ValidationRule):
    """Warn when the policy denies by default and allows nothing."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.network.default is NetworkDefault.DENY and not spec.network.allow:
            yield ValidationIssue.warning(
                "network denies all domains and allowlist is empty — "
                "the agent will have no network access"
            )


class WidePrivateRangeRule(ValidationRule):
    """Warn about allow rules that open a large slice of local/private address space."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for rule in _parsed(spec.network.allow):
            if not isinstance(rule, AddressRule):
                continue
            network = rule.network
            if network.prefixlen < _NARROWEST_WIDE_PREFIX[network.version] and overlaps_protected(
                network
            ):
                yield ValidationIssue.warning(
                    f"network rule '{rule}' opens a wide local/private range "
                    f"(shorter than /{_NARROWEST_WIDE_PREFIX[network.version]})"
                )


class HostWithoutPortRule(ValidationRule):
    """``host`` without ports exposes every service on the user's machine."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for rule in _parsed(spec.network.allow):
            if isinstance(rule, HostRule) and rule.ports.is_all:
                yield ValidationIssue.warning(
                    f"network rule '{rule}' allows every port on your machine; "
                    "list the ports you need, e.g. 'host:5432'"
                )
