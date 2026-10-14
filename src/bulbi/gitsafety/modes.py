"""``[git] mode``: how a box reaches the project's git metadata (one :class:`GitMode` each).

To add a mode, subclass :class:`GitMode` and register it in :meth:`GitModes.builtin`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import ClassVar

from bulbi.agents.ports import ContainerHandle
from bulbi.container.identity import BoxIdentity
from bulbi.container.mounts import GitMetadataMounts, IsolatedGitMetadata, ProtectedGitMetadata
from bulbi.errors import SandboxError
from bulbi.gitsafety.isolated import BoxClones, checkout_slots
from bulbi.gitsafety.layout import WORKTREE_ADMIN_DIR
from bulbi.project.locator import Project
from bulbi.spec import GitModeKind


class GitMode(ABC):
    """Plugs into the mount planner (what the box sees) and the session (when to prepare)."""

    kind: ClassVar[GitModeKind]

    @abstractmethod
    def metadata_mounts(self) -> GitMetadataMounts:
        """The mounts that expose (or replace) the project's git directory."""

    def provision(self, image: str) -> None:  # noqa: B027 - optional hook
        """Before a box (new or stopped) starts."""

    def attach(self, image: str, box: ContainerHandle) -> None:  # noqa: B027 - optional hook
        """Before a session attaches to the running box."""


class GuardedGitMode(GitMode):
    """§2: the host's git metadata, read-only where git obeys it, scanned after sessions."""

    kind = GitModeKind.GUARDED

    def metadata_mounts(self) -> GitMetadataMounts:
        return ProtectedGitMetadata()


class IsolatedGitMode(GitMode):
    """§3: the box gets its own clone; the host's git directory is never mounted."""

    kind = GitModeKind.ISOLATED

    def __init__(self, project: Project, identity: BoxIdentity, clones: BoxClones) -> None:
        self._project = project
        self._volume = identity.git_volume_name
        self._clones = clones

    def metadata_mounts(self) -> GitMetadataMounts:
        return IsolatedGitMetadata(self._volume)

    def provision(self, image: str) -> None:
        self._clones.seed(image, self._volume, self._project)

    def attach(self, image: str, box: ContainerHandle) -> None:
        """A worktree created after the box started gets its admin dir in the clone."""
        git_dir = self._project.git_dir
        current = self._project.current
        for slot in checkout_slots(self._project):
            if slot.checkout != current or git_dir is None:
                continue
            head = git_dir / WORKTREE_ADMIN_DIR / slot.name / "HEAD"
            if not box.exec(["test", "-f", str(head)]).succeeded:
                self.provision(image)


GitModeFactory = Callable[[Project, BoxIdentity, BoxClones | None], GitMode]


def _isolated(project: Project, identity: BoxIdentity, clones: BoxClones | None) -> GitMode:
    if clones is None:
        raise SandboxError('[git] mode = "isolated" is not available here (no Docker volumes)')
    return IsolatedGitMode(project, identity, clones)


class GitModes:
    """Every ``[git] mode``, registered in one place."""

    def __init__(self, factories: Mapping[GitModeKind, GitModeFactory]) -> None:
        self._factories = dict(factories)

    @classmethod
    def builtin(cls) -> GitModes:
        return cls(
            {
                GitModeKind.GUARDED: lambda _project, _identity, _clones: GuardedGitMode(),
                GitModeKind.ISOLATED: _isolated,
            }
        )

    def create(
        self,
        kind: GitModeKind,
        project: Project,
        identity: BoxIdentity,
        clones: BoxClones | None = None,
    ) -> GitMode:
        return self._factories[kind](project, identity, clones)
