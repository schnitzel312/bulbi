"""Rules about the outbound network policy."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.spec import BulbiSpec, NetworkDefault
from bulbi.validation.base import ValidationIssue, ValidationRule


class OpenNetworkRule(ValidationRule):
    """Warn when the proxy lets the agent reach any domain."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.network.default is NetworkDefault.ALLOW:
            yield ValidationIssue.warning(
                "network.default is 'allow' — the agent can reach any domain. "
                "Consider using 'deny' with an explicit allowlist"
            )


class EmptyAllowlistRule(ValidationRule):
    """Warn when the policy denies by default and allows nothing."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.network.default is NetworkDefault.DENY and not spec.network.allow:
            yield ValidationIssue.warning(
                "network denies all domains and allowlist is empty — "
                "the agent will have no network access"
            )
