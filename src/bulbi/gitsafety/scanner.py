"""``GitSafetyScanner``: compares the checkouts' git metadata with the baseline (§2.2)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from bulbi.gitsafety.baseline import GitBaseline
from bulbi.gitsafety.checks import (
    ExecConfigCheck,
    ForeignPointerCheck,
    GitCheck,
    HookChangedCheck,
    NewGitDirCheck,
    ScanContext,
)
from bulbi.gitsafety.exec_keys import ExecConfigRegistry
from bulbi.gitsafety.findings import GitFinding
from bulbi.gitsafety.inventory import GitInventory
from bulbi.gitsafety.layout import within


@dataclass(frozen=True)
class ScanResult:
    """The findings, and whether the walk finished within its time budget."""

    findings: tuple[GitFinding, ...]
    complete: bool = True


class GitSafetyScanner:
    """Takes a fresh snapshot of the baseline's roots and runs every check over it.

    Pure apart from reading the filesystem: config files are read through the
    inventory's injected reader.
    """

    def __init__(
        self,
        inventory: GitInventory,
        registry: ExecConfigRegistry | None = None,
        checks: Sequence[GitCheck] | None = None,
    ) -> None:
        self._inventory = inventory
        self._registry = registry or ExecConfigRegistry.builtin()
        self._checks = tuple(checks if checks is not None else self.default_checks())

    @staticmethod
    def default_checks() -> tuple[GitCheck, ...]:
        """The §2.2 checks, in report order."""
        return (NewGitDirCheck(), ForeignPointerCheck(), ExecConfigCheck(), HookChangedCheck())

    def scan(self, baseline: GitBaseline) -> ScanResult:
        current = self._inventory.take(baseline.roots, baseline.common_dir)
        context = ScanContext(baseline, current, self._registry)
        findings = (finding for check in self._checks for finding in check.findings(context))
        return ScanResult(_without_covered(findings), current.complete)


def _without_covered(findings: Iterable[GitFinding]) -> tuple[GitFinding, ...]:
    """Drop findings inside something another finding already moves aside."""
    kept: list[GitFinding] = []
    for finding in findings:
        if any(_covers(other, finding) for other in kept):
            continue
        kept = [other for other in kept if not _covers(finding, other)]
        kept.append(finding)
    return tuple(kept)


def _covers(mover: GitFinding, other: GitFinding) -> bool:
    return mover.moves_subject and within(other.subject, mover.subject)
