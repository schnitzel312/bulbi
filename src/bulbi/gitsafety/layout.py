"""How git finds its metadata: ``.git`` entries and the pointer files between them."""

from __future__ import annotations

import os
from pathlib import Path

from bulbi.project.locator import GIT_DIR_NAME, WORKTREE_ADMIN_DIR

MODULES_DIR = "modules"
COMMONDIR_FILE = "commondir"
GITDIR_FILE = "gitdir"
CONFIG_FILE = "config"
WORKTREE_CONFIG_FILE = "config.worktree"
HOOKS_DIR = "hooks"
GITFILE_PREFIX = "gitdir:"
# Pointer files are one short line; never read more of an agent-written file.
_POINTER_READ_LIMIT = 4096

__all__ = [
    "COMMONDIR_FILE",
    "CONFIG_FILE",
    "GITDIR_FILE",
    "GIT_DIR_NAME",
    "HOOKS_DIR",
    "MODULES_DIR",
    "WORKTREE_ADMIN_DIR",
    "WORKTREE_CONFIG_FILE",
    "common_dir_of",
    "gitfile_target",
    "pointer_target",
    "within",
]


def within(path: Path, directory: Path) -> bool:
    """Whether ``path`` is ``directory`` or inside it."""
    return path == directory or directory in path.parents


def _read_head(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            return handle.read(_POINTER_READ_LIMIT).decode(errors="replace").strip()
    except OSError:
        return None


def gitfile_target(path: Path) -> Path | None:
    """Where a ``.git`` file (``gitdir: <path>``) or ``.git`` symlink sends git."""
    if path.is_symlink():
        return (path.parent / os.readlink(path)).resolve()
    content = _read_head(path)
    if content is None or not content.startswith(GITFILE_PREFIX):
        return None
    return (path.parent / content.removeprefix(GITFILE_PREFIX).strip()).resolve()


def pointer_target(path: Path) -> Path | None:
    """The path in a ``commondir``/``gitdir`` file, resolved against its directory."""
    content = _read_head(path) if path.is_file() else None
    return (path.parent / content).resolve() if content else None


def common_dir_of(git_dir: Path) -> Path:
    """The common directory git uses for ``git_dir`` (its ``commondir``, else itself)."""
    return pointer_target(git_dir / COMMONDIR_FILE) or git_dir
