"""What a scan can find (spec §2.2), and how each kind is neutralised (§2.3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from bulbi.gitsafety.quarantine import QuarantineSession


class FindingReason(StrEnum):
    """The audit-log ``reason`` of each kind of finding."""

    EXEC_CONFIG = "git_exec_config"
    NEW_GIT_DIR = "new_git_dir"
    FOREIGN_POINTER = "foreign_pointer"
    HOOK_CHANGED = "hook_changed"


@dataclass(frozen=True)
class GitFinding(ABC):
    """Git metadata the agent could use to run code on the host.

    ``path`` is what the report names; ``subject`` is what quarantine moves aside.
    """

    reason: ClassVar[FindingReason]
    path: Path

    @property
    def subject(self) -> Path:
        return self.path

    @property
    def moves_subject(self) -> bool:
        """Whether neutralising moves ``subject`` (and everything under it) aside."""
        return True

    @property
    def detail(self) -> str:
        """The key or pointer target involved, for the report and the audit log."""
        return ""

    @abstractmethod
    def describe(self) -> str:
        """One line saying what is wrong."""

    def neutralise(self, quarantine: QuarantineSession) -> str:
        """Make the finding harmless, never deleting anything; return what was done."""
        return f"moved to {quarantine.move(self, self.subject)}"


@dataclass(frozen=True)
class NewGitDirFinding(GitFinding):
    """A ``.git`` or worktree admin directory that appeared after box creation (vector C)."""

    reason: ClassVar[FindingReason] = FindingReason.NEW_GIT_DIR
    target: Path | None = None

    @property
    def detail(self) -> str:
        return "" if self.target is None else f"-> {self.target}"

    def describe(self) -> str:
        pointing = f" pointing at {self.target}" if self.target is not None else ""
        return f"new git metadata created after the box started{pointing}"


@dataclass(frozen=True)
class ForeignPointerFinding(GitFinding):
    """A pointer file (``.git``, ``commondir``, ``gitdir``) now sending git elsewhere."""

    reason: ClassVar[FindingReason] = FindingReason.FOREIGN_POINTER
    target: Path | None = None
    moved: Path | None = None

    @property
    def subject(self) -> Path:
        return self.moved or self.path

    @property
    def detail(self) -> str:
        return f"-> {self.target}"

    def describe(self) -> str:
        return f"points git at {self.target}, outside this project's git directories"


@dataclass(frozen=True)
class ExecConfigFinding(GitFinding):
    """A config key that runs a program, set to a value the baseline did not have.

    ``key`` is ``None`` when git cannot parse the file at all.
    """

    reason: ClassVar[FindingReason] = FindingReason.EXEC_CONFIG
    key: str | None = None
    values: tuple[str | None, ...] = ()
    trusted: tuple[str | None, ...] = field(default=(), compare=False)

    @property
    def moves_subject(self) -> bool:
        return self.key is None

    @property
    def detail(self) -> str:
        return self.key or "unparseable config"

    def describe(self) -> str:
        if self.key is None:
            return "config file git cannot parse changed"
        shown = ", ".join(repr(value) for value in self.values)
        return f"sets {self.key} = {shown} (runs a program)"

    def neutralise(self, quarantine: QuarantineSession) -> str:
        if self.key is None:
            return super().neutralise(quarantine)
        backup = quarantine.comment_out(self, self.path, self.key, self.trusted)
        return f"commented out {self.key} (backup at {backup})"


@dataclass(frozen=True)
class HookChangedFinding(GitFinding):
    """An executable hook that is new or differs from the baseline."""

    reason: ClassVar[FindingReason] = FindingReason.HOOK_CHANGED

    def describe(self) -> str:
        return "executable git hook added or changed"
