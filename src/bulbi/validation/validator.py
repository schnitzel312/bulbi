"""Runs every validation rule over a spec."""

from __future__ import annotations

from collections.abc import Sequence

from bulbi.spec import BulbiSpec
from bulbi.tools import ToolRegistry
from bulbi.validation.base import ValidationResult, ValidationRule
from bulbi.validation.rules import (
    EmptyAllowlistRule,
    InterpreterToolsRule,
    KnownToolsRule,
    MountsPresentRule,
    OpenNetworkRule,
    ProfilesNarrowRule,
    ResourceLimitsRule,
    SecretHostsRule,
    SecretSourceRule,
    WritableMountRule,
)


class SpecValidator:
    """Applies an ordered list of rules and collects their issues."""

    def __init__(self, rules: Sequence[ValidationRule]) -> None:
        self._rules = tuple(rules)

    @classmethod
    def default(cls, tools: ToolRegistry) -> SpecValidator:
        """The built-in rule set, in the order issues are reported."""
        return cls(
            [
                KnownToolsRule(tools),
                MountsPresentRule(),
                WritableMountRule(),
                OpenNetworkRule(),
                EmptyAllowlistRule(),
                ProfilesNarrowRule(),
                SecretSourceRule(),
                SecretHostsRule(),
                ResourceLimitsRule(),
                InterpreterToolsRule(tools),
            ]
        )

    def validate(self, spec: BulbiSpec) -> ValidationResult:
        return ValidationResult.from_issues(
            issue for rule in self._rules for issue in rule.check(spec)
        )
