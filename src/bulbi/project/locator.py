"""Which project a directory belongs to (spec §8.1, §9).

In a git repository the project is the repository itself, identified by its shared git
directory, so every worktree maps to the same project (and box). Outside git the project
is the directory itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from bulbi.project.git import GitClient, SubprocessGit

GIT_DIR_NAME = ".git"
WORKTREE_ADMIN_DIR = "worktrees"


@dataclass(frozen=True)
class Project:
    """A project and its checkouts.

    Attributes:
        key: What identifies the project: the real path of the shared git directory,
            or the directory itself outside git.
        root: The main checkout; its ``bulbi.toml`` and ``.bulbi/`` are authoritative.
        current: The checkout the command was started from.
        cwd: The directory the command was started from (a session's working directory).
        worktrees: Every checkout including ``root`` (git only).
        git_dir: The shared git directory (git only).
    """

    key: Path
    root: Path
    current: Path
    cwd: Path
    worktrees: tuple[Path, ...] = ()
    git_dir: Path | None = None

    @property
    def is_git(self) -> bool:
        return self.git_dir is not None

    @property
    def linked_worktrees(self) -> tuple[Path, ...]:
        """Checkouts other than the main one."""
        return tuple(path for path in self.worktrees if path != self.root)

    @classmethod
    def plain(cls, directory: Path) -> Project:
        """A project that is not under git."""
        root = directory.resolve()
        return cls(key=root, root=root, current=root, cwd=root)

    def admin_dir(self, worktree: Path) -> Path | None:
        """The ``.git/worktrees/<name>`` directory of a linked worktree."""
        dot_git = worktree / GIT_DIR_NAME
        if self.git_dir is None or not dot_git.is_file():
            return None
        content = dot_git.read_text().strip()
        if not content.startswith("gitdir:"):
            return None
        admin = (worktree / content.removeprefix("gitdir:").strip()).resolve()
        return admin if WORKTREE_ADMIN_DIR in admin.parts else None


class ProjectLocator:
    """Finds the :class:`Project` for a working directory."""

    def __init__(self, git: GitClient | None = None) -> None:
        self._git = git or SubprocessGit()

    def locate(self, cwd: Path) -> Project:
        cwd = cwd.resolve()
        git_dir = self._git.common_dir(cwd)
        current = self._git.toplevel(cwd)
        if git_dir is None or current is None:
            return Project.plain(cwd)
        git_dir = git_dir.resolve()
        # TODO(bulbi): bare repositories (no main checkout) use the current checkout.
        root = git_dir.parent if git_dir.name == GIT_DIR_NAME else current
        worktrees = tuple(self._git.worktrees(cwd)) or (root,)
        return Project(
            key=git_dir, root=root, current=current, cwd=cwd, worktrees=worktrees, git_dir=git_dir
        )
