"""Rules about named profiles."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.spec import BulbiSpec, ProfileMerger
from bulbi.validation.base import ValidationIssue, ValidationRule


class ProfilesNarrowRule(ValidationRule):
    """Every profile may only narrow the root spec (rules owned by ProfileMerger)."""

    def __init__(self, merger: ProfileMerger | None = None) -> None:
        self._merger = merger or ProfileMerger()

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for name, profile in spec.profiles.items():
            for violation in self._merger.violations(spec, profile):
                yield ValidationIssue.error(f"profile '{name}' {violation}")
