"""Rules about resource limits."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.errors import SpecError
from bulbi.spec import BulbiSpec
from bulbi.validation.base import ValidationIssue, ValidationRule


class ResourceLimitsRule(ValidationRule):
    """Limits must be usable by Docker: a positive CPU count and a parseable memory size."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if not isinstance(spec.limits.cpu, int) or spec.limits.cpu < 1:
            yield ValidationIssue.error(
                f"limits.cpu must be a positive integer, got {spec.limits.cpu!r}"
            )
        try:
            spec.limits.memory_bytes()
        except SpecError as exc:
            yield ValidationIssue.error(f"limits.memory: {exc}")
