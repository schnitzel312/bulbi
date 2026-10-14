"""Rules about what the box can reach on the host filesystem (spec §3.6, §9.2)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from bulbi.container.mounts import PROJECT_MOUNT_PATH, is_worktree_container
from bulbi.project.locator import Project
from bulbi.spec import BulbiSpec
from bulbi.validation.base import ValidationIssue, ValidationRule

DOCKER_SOCKET_NAME = "docker.sock"
# Where Docker, Docker Desktop, Colima, OrbStack and Rancher put the daemon socket.
KNOWN_DOCKER_SOCKETS = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "~/.docker/run/docker.sock",
    "~/.docker/desktop/docker.sock",
    "~/.colima/default/docker.sock",
    "~/.orbstack/run/docker.sock",
    "~/.rd/docker.sock",
)


class _HostPaths:
    """Resolves mount paths the way the mount planner does."""

    def __init__(self, project: Project | None, home: Path | None) -> None:
        self.home = (home or Path.home()).resolve()
        self.root = project.root if project else Path.cwd().resolve()

    def resolve(self, raw: str) -> Path:
        if raw.startswith("~"):
            return Path(raw.replace("~", str(self.home), 1)).resolve()
        path = Path(raw)
        return path.resolve() if path.is_absolute() else (self.root / path).resolve()


class DockerSocketMountRule(ValidationRule):
    """A Docker socket in the box is a full host escape: mounting one is an error."""

    def __init__(self, project: Project | None = None, home: Path | None = None) -> None:
        self._paths = _HostPaths(project, home)

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        sockets = [self._paths.resolve(path) for path in KNOWN_DOCKER_SOCKETS]
        for mount in spec.mounts:
            source = self._paths.resolve(mount.path)
            exposed = (
                source.name == DOCKER_SOCKET_NAME
                or (source / DOCKER_SOCKET_NAME).exists()
                or any(
                    socket.exists() and (socket == source or source in socket.parents)
                    for socket in sockets
                )
            )
            if exposed:
                yield ValidationIssue.error(
                    f"mount '{mount.path}' is or contains a Docker socket, which would let "
                    "the agent control Docker on your machine"
                )


class BroadMountRule(ValidationRule):
    """Warn about mounting ``/``, the home directory, or anything above it."""

    def __init__(self, project: Project | None = None, home: Path | None = None) -> None:
        self._paths = _HostPaths(project, home)

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        home = self._paths.home
        for mount in spec.mounts:
            source = self._paths.resolve(mount.path)
            if source == Path("/") or source == home or source in home.parents:
                yield ValidationIssue.warning(
                    f"mount '{mount.path}' exposes your whole home directory or more to the box"
                )


class WorktreeDirsRule(ValidationRule):
    """``[project] worktree_dirs`` may only hold worktrees of this repository."""

    def __init__(self, project: Project | None = None, home: Path | None = None) -> None:
        self._project = project
        self._paths = _HostPaths(project, home)

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        worktrees = self._project.worktrees if self._project else ()
        for raw in spec.project.worktree_dirs:
            if not is_worktree_container(self._paths.resolve(raw), worktrees):
                yield ValidationIssue.error(
                    f"project.worktree_dirs entry '{raw}' must contain only worktrees of "
                    "this repository"
                )
        if spec.project.worktree_dirs and not any(
            mount.path == PROJECT_MOUNT_PATH for mount in spec.mounts
        ):
            yield ValidationIssue.warning(
                "project.worktree_dirs has no effect without a [[mount]] for path '.'"
            )
