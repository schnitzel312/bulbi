"""Planning the bind mounts that expose host files to a box."""

from __future__ import annotations

import glob
from dataclasses import dataclass
from pathlib import Path

from bulbi.constants import CONTAINER_WORKSPACE, SPEC_FILENAME
from bulbi.spec import BulbiSpec, MountSpec

PROJECT_MOUNT_PATH = "."
MASK_SOURCE = "/dev/null"
GIT_MAIN_TARGET = f"{CONTAINER_WORKSPACE}/.git-main"
_GITDIR_PREFIX = "gitdir:"
_WORKTREES_DIR = "worktrees"


@dataclass(frozen=True)
class BindMount:
    """A host path bound into the container."""

    source: str
    target: str
    read_only: bool


class MountPlanner:
    """Turns a spec's mounts into bind mounts for one project.

    Besides the spec's mounts this masks excluded files with ``/dev/null``, mounts the
    spec file read-only (so the agent cannot loosen its own sandbox), and, for a git
    worktree, mounts the main repository so git keeps working inside the box.
    """

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root

    def plan(self, spec: BulbiSpec) -> list[BindMount]:
        mounts: list[BindMount] = []
        for mount in spec.mounts:
            mounts.extend(self._spec_mount(mount))
        mounts.extend(self._spec_file_mount())
        mounts.extend(self._git_main_mount())
        return mounts

    def _spec_mount(self, mount: MountSpec) -> list[BindMount]:
        source = self._host_path(mount.path)
        target = (
            CONTAINER_WORKSPACE
            if mount.path == PROJECT_MOUNT_PATH
            else f"{CONTAINER_WORKSPACE}/{source.name}"
        )
        planned = [BindMount(str(source), target, read_only=not mount.is_writable)]
        planned.extend(
            BindMount(MASK_SOURCE, f"{target}/{excluded}", read_only=True)
            for excluded in self._excluded_files(source, mount.exclude)
        )
        return planned

    @staticmethod
    def _excluded_files(source: Path, patterns: list[str]) -> list[Path]:
        """Existing files under ``source`` matching the exclude globs, relative to it."""
        return [
            Path(match).relative_to(source)
            for pattern in patterns
            for match in glob.glob(str(source / pattern))
        ]

    def _spec_file_mount(self) -> list[BindMount]:
        spec_path = self._project_root / SPEC_FILENAME
        if not spec_path.exists():
            return []
        return [BindMount(str(spec_path), f"{CONTAINER_WORKSPACE}/{SPEC_FILENAME}", True)]

    def _git_main_mount(self) -> list[BindMount]:
        git_dir = self._worktree_main_git_dir()
        return [BindMount(str(git_dir), GIT_MAIN_TARGET, False)] if git_dir else []

    def _host_path(self, raw: str) -> Path:
        if raw.startswith("~"):
            return Path(raw).expanduser().resolve()
        path = Path(raw)
        return path if path.is_absolute() else (self._project_root / path).resolve()

    def _worktree_main_git_dir(self) -> Path | None:
        """For a git worktree (``.git`` is a file), the main repository's git directory."""
        dot_git = self._project_root / ".git"
        if not dot_git.is_file():
            return None
        content = dot_git.read_text().strip()
        if not content.startswith(_GITDIR_PREFIX):
            return None
        git_dir = (self._project_root / content.removeprefix(_GITDIR_PREFIX).strip()).resolve()
        if _WORKTREES_DIR in git_dir.parts:
            return Path(*git_dir.parts[: git_dir.parts.index(_WORKTREES_DIR)])
        return git_dir
