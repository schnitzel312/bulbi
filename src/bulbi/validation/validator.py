"""Runs every validation rule over a spec."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from bulbi.project.locator import Project
from bulbi.spec import BulbiSpec
from bulbi.tools import ToolRegistry
from bulbi.validation.base import ValidationResult, ValidationRule
from bulbi.validation.rules import (
    AllowModeWithoutDenyRule,
    BroadMountRule,
    DenyEqualsAllowRule,
    DockerSocketMountRule,
    EmptyAllowlistRule,
    HostWithoutPortRule,
    IdleTimeoutRule,
    InterpreterToolsRule,
    KnownToolsRule,
    MountsPresentRule,
    OpenNetworkRule,
    ProfilesNarrowRule,
    ResourceLimitsRule,
    RuleSyntaxRule,
    SecretHostsRule,
    SecretSourceRule,
    WidePrivateRangeRule,
    WorktreeDirsRule,
    WritableMountRule,
)


class SpecValidator:
    """Applies an ordered list of rules and collects their issues."""

    def __init__(self, rules: Sequence[ValidationRule]) -> None:
        self._rules = tuple(rules)

    @classmethod
    def default(
        cls, tools: ToolRegistry, project: Project | None = None, home: Path | None = None
    ) -> SpecValidator:
        """The built-in rule set, in the order issues are reported.

        ``project`` and ``home`` resolve mount paths for the filesystem rules.
        """
        return cls(
            [
                KnownToolsRule(tools),
                MountsPresentRule(),
                WritableMountRule(),
                DockerSocketMountRule(project, home),
                BroadMountRule(project, home),
                WorktreeDirsRule(project, home),
                RuleSyntaxRule(),
                DenyEqualsAllowRule(),
                OpenNetworkRule(),
                AllowModeWithoutDenyRule(),
                EmptyAllowlistRule(),
                WidePrivateRangeRule(),
                HostWithoutPortRule(),
                ProfilesNarrowRule(),
                SecretSourceRule(),
                SecretHostsRule(),
                ResourceLimitsRule(),
                IdleTimeoutRule(),
                InterpreterToolsRule(),
            ]
        )

    def validate(self, spec: BulbiSpec) -> ValidationResult:
        return ValidationResult.from_issues(
            issue for rule in self._rules for issue in rule.check(spec)
        )
