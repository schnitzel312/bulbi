"""The checks of a git-safety scan (spec §2.2), one :class:`GitCheck` per concern.

To add a check, subclass :class:`GitCheck` and add it to
:meth:`bulbi.gitsafety.scanner.GitSafetyScanner.default_checks`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from bulbi.gitsafety.baseline import GitBaseline
from bulbi.gitsafety.exec_keys import ExecConfigRegistry
from bulbi.gitsafety.findings import (
    ExecConfigFinding,
    ForeignPointerFinding,
    GitFinding,
    HookChangedFinding,
    NewGitDirFinding,
)
from bulbi.gitsafety.inventory import AdminDir, GitSnapshot
from bulbi.gitsafety.layout import (
    COMMONDIR_FILE,
    GITDIR_FILE,
    MODULES_DIR,
    WORKTREE_ADMIN_DIR,
    gitfile_target,
    within,
)


@dataclass(frozen=True)
class ScanContext:
    """The baseline, the current snapshot, and what counts as a legitimate git layout."""

    baseline: GitBaseline
    current: GitSnapshot
    registry: ExecConfigRegistry

    def box_writable(self, path: Path) -> bool:
        return self.baseline.box_writable(path)

    @cached_property
    def _repositories(self) -> tuple[Path, ...]:
        """Git directories that may host worktrees and submodules: the project's own,
        and every repository that already existed when the box was created."""
        known = [
            path
            for path, entry in self.baseline.snapshot.entries.items()
            if entry.kind.is_repository
        ]
        if self.baseline.common_dir is not None:
            known.insert(0, self.baseline.common_dir)
        return tuple(dict.fromkeys(known))

    def legitimate_target(self, target: Path | None) -> bool:
        """Whether a ``.git`` pointer leads into a known repository's worktrees or modules."""
        if target is None:
            return False
        return any(
            target != repository / area and within(target, repository / area)
            for repository in self._repositories
            for area in (WORKTREE_ADMIN_DIR, MODULES_DIR)
        )

    @staticmethod
    def consistent_admin_dir(admin: Path, state: AdminDir) -> bool:
        """``commondir`` leads to the repository holding ``admin``, and ``gitdir`` (if its
        checkout still exists) names a ``.git`` file pointing straight back."""
        if state.commondir != admin.parent.parent:
            return False
        return state.gitdir is None or points_back(state.gitdir, admin)


def points_back(gitfile: Path, admin: Path) -> bool:
    """A missing checkout is a stale (prunable) worktree; an existing one must point back."""
    if not (gitfile.exists() or gitfile.is_symlink()):
        return True
    return gitfile.is_file() and gitfile_target(gitfile) == admin


class GitCheck(ABC):
    """One kind of dangerous change between the baseline and now."""

    @abstractmethod
    def findings(self, context: ScanContext) -> Iterator[GitFinding]:
        """Yield every finding of this kind."""


class NewGitDirCheck(GitCheck):
    """§2.2.1: ``.git`` entries and worktree admin dirs created after box start.

    A new ``.git`` *directory* is always a finding, and so is a new directory shaped
    like a repository (``HEAD``, ``objects/``, ``refs/``), which git uses as one when
    run inside it. A new ``.git`` file or link is one
    unless it is an ordinary linked checkout (pointing into a known repository's
    ``worktrees/`` or ``modules/``), and a new admin dir is one unless its pointers
    are consistent: ``git worktree add`` and ``git submodule`` keep working, while the
    pointers and configs they create are checked again by every scan.
    """

    def findings(self, context: ScanContext) -> Iterator[GitFinding]:
        known = context.baseline.snapshot
        for path, entry in context.current.entries.items():
            previous = known.entries.get(path)
            if not context.box_writable(path) or (previous and previous.kind is entry.kind):
                continue
            if entry.kind.is_repository:
                yield NewGitDirFinding(path)
            elif not context.legitimate_target(entry.target):
                yield NewGitDirFinding(path, entry.target)
        for admin, state in context.current.admin_dirs.items():
            if admin in known.admin_dirs or not context.box_writable(admin):
                continue
            if not context.consistent_admin_dir(admin, state):
                yield NewGitDirFinding(admin, state.commondir)


class ForeignPointerCheck(GitCheck):
    """§2.2.2: baseline pointer files that now lead outside the project's git dirs."""

    def findings(self, context: ScanContext) -> Iterator[GitFinding]:
        known = context.baseline.snapshot
        for path, entry in context.current.entries.items():
            previous = known.entries.get(path)
            if (
                entry.kind.is_repository
                or previous is None
                or previous.kind is not entry.kind
                or previous.target == entry.target
                or not context.box_writable(path)
                or context.legitimate_target(entry.target)
            ):
                continue
            yield ForeignPointerFinding(path, entry.target)
        for admin, state in context.current.admin_dirs.items():
            before = known.admin_dirs.get(admin)
            if before is None:
                continue
            commondir, gitdir = admin / COMMONDIR_FILE, admin / GITDIR_FILE
            expected = (before.commondir, admin.parent.parent)
            if context.box_writable(commondir) and state.commondir not in expected:
                yield ForeignPointerFinding(commondir, state.commondir, moved=admin)
            elif (
                context.box_writable(gitdir)
                and state.gitdir != before.gitdir
                and state.gitdir is not None
                and not points_back(state.gitdir, admin)
            ):
                yield ForeignPointerFinding(gitdir, state.gitdir, moved=admin)


class ExecConfigCheck(GitCheck):
    """§2.2.3: config files git reads that set an exec-capable key to a new value."""

    def findings(self, context: ScanContext) -> Iterator[GitFinding]:
        known = context.baseline.snapshot.configs
        for path, state in context.current.configs.items():
            before = known.get(path)
            if not context.box_writable(path) or (before and before.digest == state.digest):
                continue
            if state.entries is None:
                yield ExecConfigFinding(path)
                continue
            trusted = set(before.entries or ()) if before else set()
            untrusted: dict[str, list[str | None]] = {}
            for entry in state.entries:
                if entry not in trusted and context.registry.is_exec(entry.key, entry.value):
                    untrusted.setdefault(entry.key, []).append(entry.value)
            for key, values in untrusted.items():
                kept = tuple(entry.value for entry in trusted if entry.key == key)
                yield ExecConfigFinding(path, key, tuple(values), kept)


class HookChangedCheck(GitCheck):
    """§2.2.4: executable hooks that are new or differ from the baseline."""

    def findings(self, context: ScanContext) -> Iterator[GitFinding]:
        known = context.baseline.snapshot.hooks
        for path, digest in context.current.hooks.items():
            if context.box_writable(path) and known.get(path) != digest:
                yield HookChangedFinding(path)
