"""Orchestrating one sandboxed run: image, proxy, container, command, cleanup."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from bulbi.agents import Agent
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.manager import BoxManager, RunningBox
from bulbi.container.mounts import MountPlanner
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.image import ImageBuilder
from bulbi.proxy import AuditLogWriter, ProxyServer, audit_log_path, policy_for
from bulbi.sandbox.observer import SandboxObserver
from bulbi.spec import BulbiSpec


@dataclass(frozen=True)
class SandboxServices:
    """The collaborators a session uses to talk to Docker and the host."""

    images: ImageBuilder
    boxes: BoxManager
    terminal: TerminalExec
    environment: EnvironmentBuilder = field(default_factory=EnvironmentBuilder)


class SandboxSession:
    """Context manager that brings a box up on entry and tears it down on exit.

    Entering builds (or reuses) the image, starts the proxy, starts the container,
    and lets the agent prepare it. Exiting stops the container, then the proxy, even
    if entering failed half-way.
    """

    def __init__(
        self,
        spec: BulbiSpec,
        project_root: Path,
        agent: Agent,
        services: SandboxServices,
        observer: SandboxObserver | None = None,
    ) -> None:
        self._spec = spec
        self._project_root = project_root
        self._agent = agent
        self._services = services
        self._observer = observer or SandboxObserver()
        self._cleanup = ExitStack()
        self._box: RunningBox | None = None

    def __enter__(self) -> SandboxSession:
        try:
            self._start()
        except BaseException:
            self._cleanup.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._cleanup.close()

    def run(self, command: Sequence[str], label: str) -> int:
        """Run ``command`` interactively in the box and return its exit code."""
        if self._box is None:
            raise SandboxError("sandbox session is not started")
        self._observer.running(label, command)
        return self._services.terminal.run(self._box.id, command)

    def _start(self) -> None:
        self._observer.building_image(self._spec)
        image_tag = self._services.images.build(self._spec, self._agent)

        proxy = ProxyServer(
            policy_for(self._spec.network),
            AuditLogWriter(audit_log_path(self._project_root)),
        )
        proxy_port = proxy.start()
        self._cleanup.callback(proxy.stop)

        self._observer.starting_container()
        environment = self._services.environment.build(self._agent, proxy_port)
        box = self._services.boxes.start(
            self._spec,
            self._project_root,
            image_tag,
            MountPlanner(self._project_root).plan(self._spec),
            environment,
        )
        self._cleanup.callback(self._services.boxes.stop, box.id)
        self._agent.prepare_container(box.handle, environment)
        self._box = box
