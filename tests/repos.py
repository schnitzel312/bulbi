"""Real git repositories with worktrees, built in temporary directories for tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

_GIT_IDENTITY = ["-c", "user.name=Bulbi Tests", "-c", "user.email=tests@bulbi.invalid"]


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *_GIT_IDENTITY, *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def make_repo(path: Path) -> Path:
    """A repository with one commit at ``path``; returns its resolved path."""
    path.mkdir(parents=True)
    git(path, "init", "-q", "-b", "main")
    (path / "README").write_text("hello\n")
    git(path, "add", "README")
    git(path, "commit", "-q", "-m", "initial")
    return path.resolve()


def add_worktree(repo: Path, path: Path, branch: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    git(repo, "worktree", "add", "-q", "-b", branch, str(path))
    return path.resolve()
