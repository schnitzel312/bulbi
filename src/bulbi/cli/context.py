"""The CLI's composition root: builds and hands out every collaborator a command needs."""

from __future__ import annotations

from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any

from rich.console import Console

from bulbi.agents import Agent, AgentRegistry
from bulbi.constants import SPEC_FILENAME
from bulbi.container.gateway import GatewayManager
from bulbi.container.gitvolume import GitVolumeManager
from bulbi.container.manager import BoxManager
from bulbi.container.sessions import DockerSessionTracker, SessionTracker
from bulbi.container.terminal import TerminalExec
from bulbi.detection import DetectorRegistry
from bulbi.docker_sdk import connect_to_docker, docker_errors
from bulbi.gateway.audit import audit_log_path
from bulbi.gateway.config import HostAccess
from bulbi.gitsafety.guard import GitGuard
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.image.gateway import GatewayImageBuilder
from bulbi.project import GitClient, Project, ProjectLocator
from bulbi.sandbox import BoxOrchestrator, SandboxObserver, SandboxServices
from bulbi.sandbox.host import current_user, detect_host_access
from bulbi.secrets import SecretReaders
from bulbi.spec import BulbiSpec, ProfileMerger, SpecLoader
from bulbi.tools import ToolRegistry
from bulbi.validation import SpecValidator

DockerFactory = Callable[[], Any]


class AppContext:
    """Shared services for one CLI invocation.

    Everything that touches the outside world (working directory, console, Docker,
    the ``docker exec`` runner, host environment) is injectable, so commands can be
    tested with fakes. The Docker client is created lazily, on first use.
    """

    def __init__(  # noqa: PLR0913 - keyword-only injection points with defaults
        self,
        *,
        project_root: Path,
        console: Console | None = None,
        docker_factory: DockerFactory = connect_to_docker,
        terminal: TerminalExec | None = None,
        secret_readers: SecretReaders | None = None,
        tools: ToolRegistry | None = None,
        agents: AgentRegistry | None = None,
        detectors: DetectorRegistry | None = None,
        spec_loader: SpecLoader | None = None,
        host_access: HostAccess | None = None,
        git: GitClient | None = None,
    ) -> None:
        self.project_root = project_root
        self.console = console or Console()
        self.tools = tools or ToolRegistry.builtin()
        self.agents = agents or AgentRegistry.builtin()
        self.detectors = detectors or DetectorRegistry.builtin()
        self._spec_loader = spec_loader or SpecLoader()
        self._profiles = ProfileMerger()
        self._docker_factory = docker_factory
        self._terminal = terminal or TerminalExec()
        self.secret_readers = secret_readers or SecretReaders.builtin()
        self._host_access = host_access or detect_host_access()
        self._locator = ProjectLocator(git)

    @cached_property
    def project(self) -> Project:
        """The project of the working directory (all worktrees of a repo are one project)."""
        return self._locator.locate(self.project_root)

    @cached_property
    def validator(self) -> SpecValidator:
        return SpecValidator.default(self.tools, self.project)

    def load_spec(self, profile: str | None = None) -> BulbiSpec:
        """The main checkout's spec (spec §9.3), narrowed by ``profile`` when one is given."""
        spec = self._spec_loader.load(self.project.root)
        return self._profiles.resolve(spec, profile) if profile else spec

    def worktree_spec_differs(self) -> bool:
        """Whether the current worktree carries its own, different ``bulbi.toml``."""
        project = self.project
        if project.current == project.root:
            return False
        own, main = project.current / SPEC_FILENAME, project.root / SPEC_FILENAME
        return own.is_file() and (not main.is_file() or own.read_bytes() != main.read_bytes())

    @property
    def state_dir(self) -> Path:
        """The main checkout's ``.bulbi/`` (lock, audit log, git baseline, quarantine)."""
        return audit_log_path(self.project.root).parent

    def git_guard(self, spec: BulbiSpec, profile: str | None = None) -> GitGuard:
        return GitGuard.for_project(spec.git, self.project.root, self.state_dir, profile)

    def agent_for(self, spec: BulbiSpec) -> Agent:
        return self.agents.resolve(spec.box.agent)

    @cached_property
    def docker(self) -> Any:
        with docker_errors("Docker is not available"):
            return self._docker_factory()

    def box_manager(self) -> BoxManager:
        return BoxManager(self.docker)

    def gateway_manager(self) -> GatewayManager:
        return GatewayManager(self.docker)

    def session_tracker(self) -> SessionTracker:
        return DockerSessionTracker(self.docker)

    def git_volumes(self) -> GitVolumeManager:
        return GitVolumeManager(self.docker)

    def sandbox_services(self) -> SandboxServices:
        return SandboxServices(
            images=ImageBuilder(self.docker, DockerfileBuilder(self.tools)),
            gateway_images=GatewayImageBuilder(self.docker),
            boxes=self.box_manager(),
            gateways=self.gateway_manager(),
            sessions=self.session_tracker(),
            terminal=self._terminal,
            secret_readers=self.secret_readers,
            host_access=self._host_access,
            log_owner=current_user(),
            git_volumes=self.git_volumes(),
        )

    def orchestrator(
        self,
        spec: BulbiSpec,
        profile: str | None = None,
        observer: SandboxObserver | None = None,
        services: SandboxServices | None = None,
    ) -> BoxOrchestrator:
        return BoxOrchestrator(
            spec,
            self.project,
            self.agent_for(spec),
            services or self.sandbox_services(),
            observer,
            profile,
        )
