"""Rules about the ``[box]`` section."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.errors import SpecError
from bulbi.spec import BulbiSpec
from bulbi.validation.base import ValidationIssue, ValidationRule


class IdleTimeoutRule(ValidationRule):
    """``box.idle_timeout`` must be a duration like ``0``, ``90s``, ``10m`` or ``1h``."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        try:
            spec.box.idle_timeout_seconds()
        except SpecError as exc:
            yield ValidationIssue.error(str(exc))
