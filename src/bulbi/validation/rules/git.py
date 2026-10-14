"""Rules about ``[git]`` (docs/specs/git-safety.md)."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.errors import SpecError, ToolError
from bulbi.gitsafety.isolated import REQUIRED_TOOL
from bulbi.gitsafety.layout import GIT_DIR_NAME
from bulbi.project.locator import Project
from bulbi.spec import BulbiSpec, GitModeKind
from bulbi.tools import ToolRegistry
from bulbi.validation.base import ValidationIssue, ValidationRule


class GitScanBudgetRule(ValidationRule):
    """``scan_budget`` must be a duration."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        try:
            spec.git.scan_budget_seconds()
        except SpecError as exc:
            yield ValidationIssue.error(str(exc))


class IsolatedGitRule(ValidationRule):
    """Isolated mode needs a repository with a ``.git`` directory and git in the image."""

    def __init__(self, project: Project | None = None) -> None:
        self._project = project

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        if spec.git.mode is not GitModeKind.ISOLATED:
            return
        if REQUIRED_TOOL not in _tool_names(spec):
            yield ValidationIssue.error(
                f'[git] mode = "isolated" needs "{REQUIRED_TOOL}" in [tools] allow'
            )
        git_dir = self._project.git_dir if self._project else None
        if git_dir is None or git_dir.name != GIT_DIR_NAME:
            yield ValidationIssue.error(
                '[git] mode = "isolated" needs a git repository with a .git directory'
            )


def _tool_names(spec: BulbiSpec) -> set[str]:
    names = set()
    for reference in spec.tools.allow:
        try:
            names.add(ToolRegistry.parse(reference).name)
        except ToolError:
            continue  # Reported by KnownToolsRule.
    return names
