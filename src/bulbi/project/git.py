"""The few git queries Bulbi needs, behind an interface so tests can fake them."""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]
_PORCELAIN_WORKTREE = "worktree "
_PORCELAIN_PRUNABLE = "prunable"


class GitClient(ABC):
    """Read-only repository queries. Every method returns ``None``/empty outside a repo."""

    @abstractmethod
    def common_dir(self, cwd: Path) -> Path | None:
        """The shared git directory (``git rev-parse --git-common-dir``), absolute."""

    @abstractmethod
    def toplevel(self, cwd: Path) -> Path | None:
        """The checkout containing ``cwd`` (``git rev-parse --show-toplevel``)."""

    @abstractmethod
    def worktrees(self, cwd: Path) -> list[Path]:
        """Every checkout of the repository, main first (``git worktree list``)."""


class SubprocessGit(GitClient):
    """Runs the ``git`` executable."""

    def __init__(self, runner: CommandRunner = subprocess.run) -> None:
        self._run = runner

    def _git(self, cwd: Path, *args: str) -> str | None:
        try:
            result = self._run(
                ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
            )
        except OSError:
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    def common_dir(self, cwd: Path) -> Path | None:
        output = self._git(cwd, "rev-parse", "--git-common-dir")
        return (cwd / output).resolve() if output else None

    def toplevel(self, cwd: Path) -> Path | None:
        output = self._git(cwd, "rev-parse", "--show-toplevel")
        return Path(output).resolve() if output else None

    def worktrees(self, cwd: Path) -> list[Path]:
        output = self._git(cwd, "worktree", "list", "--porcelain")
        if not output:
            return []
        paths: list[Path] = []
        for block in output.split("\n\n"):
            lines = block.splitlines()
            head = next((ln for ln in lines if ln.startswith(_PORCELAIN_WORKTREE)), None)
            if head is None or any(ln.startswith(_PORCELAIN_PRUNABLE) for ln in lines):
                continue
            path = Path(head.removeprefix(_PORCELAIN_WORKTREE)).resolve()
            if path.is_dir():
                paths.append(path)
        return paths
