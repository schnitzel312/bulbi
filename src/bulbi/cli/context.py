"""The CLI's composition root: builds and hands out every collaborator a command needs."""

from __future__ import annotations

from collections.abc import Callable
from functools import cached_property
from pathlib import Path
from typing import Any

from rich.console import Console

from bulbi.agents import Agent, AgentRegistry
from bulbi.container.docker_sdk import connect_to_docker, docker_errors
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.manager import BoxManager
from bulbi.container.terminal import TerminalExec
from bulbi.detection import DetectorRegistry
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.sandbox import SandboxServices
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
        environment: EnvironmentBuilder | None = None,
        tools: ToolRegistry | None = None,
        agents: AgentRegistry | None = None,
        detectors: DetectorRegistry | None = None,
        spec_loader: SpecLoader | None = None,
    ) -> None:
        self.project_root = project_root
        self.console = console or Console()
        self.tools = tools or ToolRegistry.builtin()
        self.agents = agents or AgentRegistry.builtin()
        self.detectors = detectors or DetectorRegistry.builtin()
        self.validator = SpecValidator.default(self.tools)
        self._spec_loader = spec_loader or SpecLoader()
        self._profiles = ProfileMerger()
        self._docker_factory = docker_factory
        self._terminal = terminal or TerminalExec()
        self._environment = environment or EnvironmentBuilder()

    def load_spec(self, profile: str | None = None) -> BulbiSpec:
        """The project's spec, narrowed by ``profile`` when one is given."""
        spec = self._spec_loader.load(self.project_root)
        return self._profiles.resolve(spec, profile) if profile else spec

    def agent_for(self, spec: BulbiSpec) -> Agent:
        return self.agents.resolve(spec.box.agent)

    @cached_property
    def docker(self) -> Any:
        with docker_errors("Docker is not available"):
            return self._docker_factory()

    def box_manager(self) -> BoxManager:
        return BoxManager(self.docker)

    def sandbox_services(self) -> SandboxServices:
        return SandboxServices(
            images=ImageBuilder(self.docker, DockerfileBuilder(self.tools)),
            boxes=self.box_manager(),
            terminal=self._terminal,
            environment=self._environment,
        )
