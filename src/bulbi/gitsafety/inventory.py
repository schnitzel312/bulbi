"""A snapshot of every piece of git metadata under the mounted checkouts (spec §2.1).

The same snapshot is the baseline at box creation and the "now" of every scan, so the
two are always compared like for like.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from bulbi.constants import LOG_DIR
from bulbi.gitsafety.config import (
    ConfigEntry,
    ConfigUnreadableError,
    GitConfigReader,
    include_target,
)
from bulbi.gitsafety.layout import (
    COMMONDIR_FILE,
    CONFIG_FILE,
    GIT_DIR_NAME,
    GITDIR_FILE,
    HOOKS_DIR,
    WORKTREE_ADMIN_DIR,
    WORKTREE_CONFIG_FILE,
    common_dir_of,
    gitfile_target,
    pointer_target,
)
from bulbi.paths import expand_home

Clock = Callable[[], float]
HOOKS_PATH_KEY = "core.hookspath"
LINK_DIGEST_PREFIX = "link:"


class EntryKind(StrEnum):
    """What a ``.git`` entry in a checkout is."""

    DIRECTORY = "dir"
    FILE = "file"  # ``gitdir: <path>``
    LINK = "link"  # a symlink named ``.git``


@dataclass(frozen=True)
class GitEntry:
    """A ``.git`` found in a checkout; ``target`` is where a file or link points."""

    kind: EntryKind
    target: Path | None = None


@dataclass(frozen=True)
class AdminDir:
    """A ``<common>/worktrees/<name>`` directory and the targets of its pointer files."""

    commondir: Path | None
    gitdir: Path | None


@dataclass(frozen=True)
class ConfigState:
    """A config file's content hash and entries (``None``: git cannot parse it)."""

    digest: str
    entries: tuple[ConfigEntry, ...] | None


@dataclass(frozen=True)
class GitSnapshot:
    """Every git metadata item found, keyed by absolute path."""

    entries: Mapping[Path, GitEntry] = field(default_factory=dict)
    admin_dirs: Mapping[Path, AdminDir] = field(default_factory=dict)
    configs: Mapping[Path, ConfigState] = field(default_factory=dict)
    hooks: Mapping[Path, str] = field(default_factory=dict)
    complete: bool = True


class _OutOfTimeError(Exception):
    """The scan budget ran out."""


class GitInventory:
    """Walks the mounted checkouts and records their git metadata.

    Directories named in ``skip`` (and ``.bulbi``) are not entered, nor are ``.git``
    directories (their contents are reached through the pointers instead). The walk
    stops when ``budget`` seconds have passed and marks the snapshot incomplete.
    """

    def __init__(
        self,
        reader: GitConfigReader,
        *,
        skip: Iterable[str] = (),
        home: Path | None = None,
        budget: float | None = None,
        clock: Clock = time.monotonic,
    ) -> None:
        self._reader = reader
        self._skip = frozenset(skip) | {GIT_DIR_NAME, LOG_DIR}
        self._home = home or Path.home()
        self._budget = budget
        self._clock = clock
        self._deadline: float | None = None

    def take(self, roots: Sequence[Path], common_dir: Path | None = None) -> GitSnapshot:
        self._deadline = None if self._budget is None else self._clock() + self._budget
        entries: dict[Path, GitEntry] = {}
        admin_dirs: dict[Path, AdminDir] = {}
        configs: dict[Path, ConfigState] = {}
        hooks: dict[Path, str] = {}
        try:
            for root in roots:
                entries.update(self._entries(root))
            git_dirs = self._git_dirs(entries, common_dir, admin_dirs)
            for git_dir, checkout in git_dirs.items():
                hooks_dirs = [git_dir / HOOKS_DIR, common_dir_of(git_dir) / HOOKS_DIR]
                for hooks_path in self._configs(git_dir, configs):
                    hooks_dirs.append(self._hooks_dir(hooks_path, checkout))
                for directory in dict.fromkeys(hooks_dirs):
                    hooks.update(self._hooks(directory))
        except _OutOfTimeError:
            return GitSnapshot(entries, admin_dirs, configs, hooks, complete=False)
        return GitSnapshot(entries, admin_dirs, configs, hooks)

    # ---- the walk ----------------------------------------------------------------------

    def _tick(self) -> None:
        if self._deadline is not None and self._clock() > self._deadline:
            raise _OutOfTimeError

    def _entries(self, root: Path) -> Iterator[tuple[Path, GitEntry]]:
        for directory, dirnames, filenames in os.walk(root):
            self._tick()
            if GIT_DIR_NAME in dirnames or GIT_DIR_NAME in filenames:
                path = Path(directory) / GIT_DIR_NAME
                yield path, self._entry(path)
            dirnames[:] = [name for name in dirnames if name not in self._skip]

    @staticmethod
    def _entry(path: Path) -> GitEntry:
        if path.is_symlink():
            return GitEntry(EntryKind.LINK, gitfile_target(path))
        if path.is_dir():
            return GitEntry(EntryKind.DIRECTORY)
        return GitEntry(EntryKind.FILE, gitfile_target(path))

    def _git_dirs(
        self,
        entries: Mapping[Path, GitEntry],
        common_dir: Path | None,
        admin_dirs: dict[Path, AdminDir],
    ) -> dict[Path, Path]:
        """Every directory git may use as GIT_DIR, mapped to the checkout it serves."""
        git_dirs: dict[Path, Path] = {}
        repositories = [common_dir] if common_dir is not None else []
        for path, entry in entries.items():
            if entry.kind is EntryKind.DIRECTORY:
                repositories.append(path)
            elif entry.target is not None and entry.target.is_dir():
                git_dirs.setdefault(entry.target, path.parent)
        for repository in dict.fromkeys(repositories):
            git_dirs.setdefault(repository, repository.parent)
            for admin, state in self._admin_dirs(repository):
                admin_dirs[admin] = state
                checkout = state.gitdir.parent if state.gitdir is not None else admin
                git_dirs.setdefault(admin, checkout)
        return git_dirs

    def _admin_dirs(self, repository: Path) -> Iterator[tuple[Path, AdminDir]]:
        try:
            children = sorted((repository / WORKTREE_ADMIN_DIR).iterdir())
        except OSError:
            return
        for admin in children:
            self._tick()
            if admin.is_dir() and not admin.is_symlink():
                yield (
                    admin,
                    AdminDir(
                        pointer_target(admin / COMMONDIR_FILE), pointer_target(admin / GITDIR_FILE)
                    ),
                )

    # ---- config files ------------------------------------------------------------------

    def _configs(self, git_dir: Path, configs: dict[Path, ConfigState]) -> Iterator[str]:
        """Record every config file git reads for ``git_dir``; yield its hooksPath values."""
        common = common_dir_of(git_dir)
        pending = [git_dir / CONFIG_FILE, git_dir / WORKTREE_CONFIG_FILE, common / CONFIG_FILE]
        seen: set[Path] = set()
        while pending:
            path = pending.pop(0)
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            state = configs.get(path) or self._config_state(path)
            configs[path] = state
            for entry in state.entries or ():
                target = include_target(entry, path, self._home)
                if target is not None:
                    pending.append(target)
                elif entry.key.lower() == HOOKS_PATH_KEY and entry.value:
                    yield entry.value

    def _config_state(self, path: Path) -> ConfigState:
        self._tick()
        digest = _digest(path)
        try:
            return ConfigState(digest, self._reader.read(path))
        except ConfigUnreadableError:
            return ConfigState(digest, None)

    # ---- hooks -------------------------------------------------------------------------

    def _hooks_dir(self, configured: str, checkout: Path) -> Path:
        path = Path(expand_home(configured, self._home))
        return path if path.is_absolute() else checkout / path

    def _hooks(self, directory: Path) -> Iterator[tuple[Path, str]]:
        try:
            children = sorted(directory.iterdir())
        except OSError:
            return
        for hook in children:
            self._tick()
            if hook.is_file() and os.access(hook, os.X_OK):
                yield hook, _hook_digest(hook)


def _digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _hook_digest(path: Path) -> str:
    if path.is_symlink():
        return LINK_DIGEST_PREFIX + os.readlink(path)
    return _digest(path)
