"""Planning the mounts that expose a project to its box (spec §3.6, §9.1-9.3).

* Every checkout of the project is mounted at **its own host path**, so git's absolute
  worktree links work and paths in agent output match the host.
* Linked worktrees whose parent directory holds nothing but worktrees of this repo are
  covered by mounting that parent once (new worktrees then appear without a restart);
  otherwise each worktree is mounted on its own. A mixed parent is never mounted.
* Read-only overlays in every checkout: ``bulbi.toml``, the shared ``.git/hooks`` and
  ``.git/config``, and each worktree's ``config.worktree`` — so the agent cannot loosen
  its sandbox or plant code that runs on the host.
* Excluded files are masked with ``/dev/null``; excluded directories with an empty
  read-only tmpfs.
"""

from __future__ import annotations

import glob
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from bulbi.constants import CONTAINER_WORKSPACE, SPEC_FILENAME
from bulbi.errors import SpecError
from bulbi.paths import expand_home
from bulbi.project.locator import Project
from bulbi.spec import BulbiSpec, MountSpec

PROJECT_MOUNT_PATH = "."
GIT_POINTER_FILE = ".git"
MASK_SOURCE = "/dev/null"
# Entries that may sit next to worktrees without making their parent "mixed".
_IGNORABLE_ENTRIES = frozenset({".DS_Store"})
# Files git follows to find the config it obeys: a writable one lets the agent point git
# at a config it controls (core.fsmonitor, core.hooksPath, ...) and run code on the host.
_PROTECTED_GIT_FILES = ("config", "config.worktree", "commondir", "gitdir")
_HOOKS_DIR = "hooks"


@dataclass(frozen=True)
class BindMount:
    """A host path bound into the container."""

    source: str
    target: str
    read_only: bool


@dataclass(frozen=True)
class TmpfsMount:
    """An empty, read-only tmpfs hiding whatever is at ``target``."""

    target: str


PlannedMount = BindMount | TmpfsMount


def is_worktree_container(directory: Path, worktrees: Iterable[Path]) -> bool:
    """Whether every entry of ``directory`` is one of ``worktrees``."""
    known = {path.resolve() for path in worktrees}
    try:
        entries = [entry for entry in directory.iterdir() if entry.name not in _IGNORABLE_ENTRIES]
    except OSError:
        return False
    return bool(entries) and all(entry.resolve() in known for entry in entries)


class MountPlanner:
    """Turns a spec's mounts into Docker mounts for one project."""

    def __init__(self, project: Project, home: Path | None = None) -> None:
        self._project = project
        self._home = home or Path.home()

    def checkout_roots(self, spec: BulbiSpec) -> list[Path]:
        """The directories mounted to expose the project's checkouts, in mount order."""
        roots = [self._project.root]
        for directory in self._worktree_dirs(spec):
            if directory not in roots:
                roots.append(directory)
        for worktree in self._project.linked_worktrees:
            if not any(_within(worktree, root) for root in roots):
                container = worktree.parent
                covered = (
                    container
                    if is_worktree_container(container, self._project.worktrees)
                    and not _within(self._project.root, container)
                    else worktree
                )
                roots.append(covered)
        return roots

    def plan(self, spec: BulbiSpec) -> list[PlannedMount]:
        mounts: list[PlannedMount] = []
        for mount in spec.mounts:
            if mount.path == PROJECT_MOUNT_PATH:
                mounts.extend(self._project_mounts(spec, mount))
            else:
                mounts.extend(self._extra_mount(mount))
        mounts.extend(self._protected_overlays(spec))
        return _deduplicated(mounts)

    # ---- the project -------------------------------------------------------------------

    def _project_mounts(self, spec: BulbiSpec, mount: MountSpec) -> Iterator[PlannedMount]:
        read_only = not mount.is_writable
        for root in self.checkout_roots(spec):
            yield BindMount(str(root), str(root), read_only)
        for checkout in self._checkouts():
            yield from self._masks(checkout, str(checkout), mount.exclude)

    def _checkouts(self) -> tuple[Path, ...]:
        return self._project.worktrees or (self._project.root,)

    def _worktree_dirs(self, spec: BulbiSpec) -> list[Path]:
        directories = []
        for raw in spec.project.worktree_dirs:
            directory = self._host_path(raw)
            if not is_worktree_container(directory, self._project.worktrees):
                raise SpecError(
                    f"project.worktree_dirs entry '{raw}' contains more than worktrees "
                    "of this repository"
                )
            directories.append(directory)
        return directories

    def _protected_overlays(self, spec: BulbiSpec) -> Iterator[PlannedMount]:
        if not any(mount.path == PROJECT_MOUNT_PATH for mount in spec.mounts):
            return
        for checkout in self._checkouts():
            for name in (SPEC_FILENAME, GIT_POINTER_FILE):
                path = checkout / name
                # A linked worktree's `.git` is a file pointing at its admin dir.
                if path.is_file():
                    yield BindMount(str(path), str(path), read_only=True)
        git_dir = self._project.git_dir
        if git_dir is None:
            return
        hooks = git_dir / _HOOKS_DIR
        # A missing hooks directory is hidden too, so it cannot be created and filled.
        yield BindMount(str(hooks), str(hooks), True) if hooks.is_dir() else TmpfsMount(str(hooks))
        linked = self._project.linked_worktrees
        admin_dirs = [git_dir, *filter(None, map(self._project.admin_dir, linked))]
        for admin in admin_dirs:
            for name in _PROTECTED_GIT_FILES:
                path = admin / name
                if path.is_file():
                    yield BindMount(str(path), str(path), read_only=True)

    # ---- other mounts ------------------------------------------------------------------

    def _extra_mount(self, mount: MountSpec) -> Iterator[PlannedMount]:
        source = self._host_path(mount.path)
        target = f"{CONTAINER_WORKSPACE}/{source.name}"
        yield BindMount(str(source), target, read_only=not mount.is_writable)
        yield from self._masks(source, target, mount.exclude)

    # ---- helpers -----------------------------------------------------------------------

    @staticmethod
    def _masks(source: Path, target: str, patterns: list[str]) -> Iterator[PlannedMount]:
        """Hide files and directories under ``source`` matching the exclude globs.

        TODO(bulbi): masking is best-effort: only paths that exist at container start are
        hidden and globs are not recursive.
        """
        for pattern in patterns:
            for match in sorted(glob.glob(str(source / pattern))):
                path = Path(match)
                masked = f"{target}/{path.relative_to(source)}"
                yield TmpfsMount(masked) if path.is_dir() else BindMount(MASK_SOURCE, masked, True)

    def _host_path(self, raw: str) -> Path:
        expanded = expand_home(raw, self._home)
        if expanded != raw:
            return Path(expanded).resolve()  # ~ paths follow symlinks, as before
        path = Path(raw)
        return path if path.is_absolute() else (self._project.root / path).resolve()


def _within(path: Path, directory: Path) -> bool:
    return path == directory or directory in path.parents


def _deduplicated(mounts: list[PlannedMount]) -> list[PlannedMount]:
    """Drop repeated targets, keeping the first (Docker rejects duplicate targets)."""
    seen: set[str] = set()
    unique = []
    for mount in mounts:
        if mount.target not in seen:
            seen.add(mount.target)
            unique.append(mount)
    return unique
