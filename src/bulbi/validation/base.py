"""Building blocks for spec validation: issues, results, and the rule interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import StrEnum

from bulbi.spec import BulbiSpec


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
    """One problem found in a spec."""

    severity: Severity
    message: str

    @classmethod
    def error(cls, message: str) -> ValidationIssue:
        return cls(Severity.ERROR, message)

    @classmethod
    def warning(cls, message: str) -> ValidationIssue:
        return cls(Severity.WARNING, message)


@dataclass(frozen=True)
class ValidationResult:
    """Errors (the spec cannot work) and warnings (it works, but is risky)."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_issues(cls, issues: Iterable[ValidationIssue]) -> ValidationResult:
        collected = list(issues)
        return cls(
            errors=[i.message for i in collected if i.severity is Severity.ERROR],
            warnings=[i.message for i in collected if i.severity is Severity.WARNING],
        )

    @property
    def ok(self) -> bool:
        return not self.errors


class ValidationRule(ABC):
    """One self-contained check on a spec."""

    @abstractmethod
    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        """Yield every issue this rule finds in ``spec``."""
