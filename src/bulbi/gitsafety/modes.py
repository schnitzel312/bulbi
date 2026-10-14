"""``[git] mode``: how a box reaches the project's git metadata (one :class:`GitMode` each).

To add a mode, subclass :class:`GitMode` and register it in :meth:`GitModes.builtin`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import ClassVar

from bulbi.agents.ports import ContainerHandle
from bulbi.constants import DOCKER_LABEL_PROJECT, LOG_DIR
from bulbi.container.gitvolume import GitVolumeManager
from bulbi.container.identity import BoxIdentity
from bulbi.container.mounts import GitMetadataMounts, IsolatedGitMetadata, ProtectedGitMetadata
from bulbi.errors import GitSafetyError, SandboxError
from bulbi.gitsafety.isolated import (
    BROKEN_HISTORY,
    HOST_OBJECTS_MOUNT,
    POINTERS_DIR,
    BoxRepo,
    HostRefsExporter,
    pointer_files,
    pointer_text,
)
from bulbi.project.locator import Project
from bulbi.spec import GitModeKind


class GitMode(ABC):
    """Plugs into the mount planner (what the box sees) and the session (when to prepare)."""

    kind: ClassVar[GitModeKind]

    @abstractmethod
    def metadata_mounts(self) -> GitMetadataMounts:
        """The mounts that expose (or replace) the project's git directory."""

    def prepare_host(self) -> None:  # noqa: B027 - optional hook
        """Before a box (new or stopped) starts."""

    def prepare_box(  # noqa: B027 - optional hook
        self, box: ContainerHandle, *, created: bool
    ) -> None:
        """After the box started, before the agent prepares it; ``created``: a new box."""

    def attach(self, box: ContainerHandle) -> None:  # noqa: B027 - optional hook
        """Before a session attaches to the running box."""


class GuardedGitMode(GitMode):
    """§2: the host's git metadata, read-only where git obeys it, scanned after sessions."""

    kind = GitModeKind.GUARDED

    def metadata_mounts(self) -> GitMetadataMounts:
        return ProtectedGitMetadata()


class IsolatedGitMode(GitMode):
    """§3: the box owns a small git dir in a volume and reads history through read-only
    alternates; host config, hooks and refs are never mounted."""

    kind = GitModeKind.ISOLATED

    def __init__(
        self,
        project: Project,
        identity: BoxIdentity,
        volumes: GitVolumeManager,
        exporter: HostRefsExporter | None = None,
    ) -> None:
        self._project = project
        self._volume = identity.git_volume_name
        self._volumes = volumes
        self._exporter = exporter or HostRefsExporter()
        self._pointers = pointer_files(project, project.root / LOG_DIR / POINTERS_DIR)

    def metadata_mounts(self) -> GitMetadataMounts:
        return IsolatedGitMetadata(self._volume, HOST_OBJECTS_MOUNT, self._pointers)

    def prepare_host(self) -> None:
        self._volumes.ensure(self._volume, {DOCKER_LABEL_PROJECT: str(self._project.key)})
        for source in self._pointers.values():
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(pointer_text(self._project, source.name))

    def prepare_box(self, box: ContainerHandle, *, created: bool) -> None:
        """Build the box repo, or bring an existing one up to date.

        An existing repo whose history the host pruned is set aside (kept in the volume)
        and rebuilt only when the box is being created (``bulbi restart``).
        """
        repo = BoxRepo(box, self._project)
        state = self._exporter.export(self._project)
        if not repo.exists():
            repo.build(state)
        elif repo.healthy():
            repo.refresh(state)
        elif created:
            repo.set_aside()
            repo.build(state)
        else:
            raise GitSafetyError(BROKEN_HISTORY)

    def attach(self, box: ContainerHandle) -> None:
        repo = BoxRepo(box, self._project)
        if not repo.healthy():
            raise GitSafetyError(BROKEN_HISTORY)
        current = self._project.admin_dir(self._project.current)
        if current is not None and not repo.has_checkout(current.name):
            # A worktree created after the box started: give it an admin dir (and its
            # branch) in the box repo.
            repo.refresh(self._exporter.export(self._project))


GitModeFactory = Callable[[Project, BoxIdentity, GitVolumeManager | None], GitMode]


def _isolated(
    project: Project, identity: BoxIdentity, volumes: GitVolumeManager | None
) -> GitMode:
    if volumes is None:
        raise SandboxError('[git] mode = "isolated" is not available here (no Docker volumes)')
    return IsolatedGitMode(project, identity, volumes)


class GitModes:
    """Every ``[git] mode``, registered in one place."""

    def __init__(self, factories: Mapping[GitModeKind, GitModeFactory]) -> None:
        self._factories = dict(factories)

    @classmethod
    def builtin(cls) -> GitModes:
        return cls(
            {
                GitModeKind.GUARDED: lambda _project, _identity, _volumes: GuardedGitMode(),
                GitModeKind.ISOLATED: _isolated,
            }
        )

    def create(
        self,
        kind: GitModeKind,
        project: Project,
        identity: BoxIdentity,
        volumes: GitVolumeManager | None = None,
    ) -> GitMode:
        return self._factories[kind](project, identity, volumes)
