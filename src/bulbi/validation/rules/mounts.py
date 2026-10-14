"""Rules about the spec's bind mounts."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.spec import BulbiSpec
from bulbi.validation.base import ValidationIssue, ValidationRule


class MountsPresentRule(ValidationRule):
    """Warn when the agent would see no project files at all."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if not spec.mounts:
            yield ValidationIssue.warning(
                "no mounts defined — the agent won't see any project files"
            )


class WritableMountRule(ValidationRule):
    """Warn when every mount is read-only, so the agent cannot change anything."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.mounts and not any(mount.is_writable for mount in spec.mounts):
            yield ValidationIssue.warning(
                "all mounts are read-only — the agent cannot write to any files"
            )
