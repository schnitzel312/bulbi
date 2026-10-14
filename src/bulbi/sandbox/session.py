"""Orchestrating one sandboxed run (spec §4).

Start, each step registered for teardown before the next begins:
build images -> dedicated network -> host relay (Linux, only with ``host`` rules) ->
gateway (wait until its rules are loaded) -> box in the gateway's network namespace ->
agent prepare -> ``docker exec`` the command. Teardown runs in reverse, always.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Callable, Iterable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from bulbi.agents import Agent
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.gateway import GatewayManager, RunningGateway, SandboxNetwork
from bulbi.container.manager import BoxManager, RunningBox
from bulbi.container.mounts import MountPlanner
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.gateway.audit import audit_log_path
from bulbi.gateway.config import GatewayConfig, HostAccess
from bulbi.gateway.policy import NetworkPolicy
from bulbi.gateway.relay import HostRelay, relay_ports
from bulbi.image import ImageBuilder
from bulbi.image.gateway import GatewayImageBuilder
from bulbi.sandbox.observer import SandboxObserver
from bulbi.spec import BulbiSpec

LINUX_SYSTEM_NAME = "Linux"

MountPlannerFactory = Callable[[Path], MountPlanner]
RelayFactory = Callable[[str, Iterable[int]], HostRelay]


def detect_host_access(system: str | None = None) -> HostAccess:
    """Linux needs the CLI's relay; Docker Desktop (macOS, Windows) has its own gateway."""
    if (system or platform.system()) == LINUX_SYSTEM_NAME:
        return HostAccess.BRIDGE_RELAY
    return HostAccess.DOCKER_DESKTOP


def current_user() -> tuple[int, int] | None:
    """The host user's (uid, gid), so files the gateway writes stay theirs."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    return (getuid(), getgid()) if getuid and getgid else None


@dataclass(frozen=True)
class SandboxServices:
    """The collaborators a session uses to talk to Docker and the host."""

    images: ImageBuilder
    gateway_images: GatewayImageBuilder
    boxes: BoxManager
    gateways: GatewayManager
    terminal: TerminalExec
    environment: EnvironmentBuilder = field(default_factory=EnvironmentBuilder)
    mount_planner_factory: MountPlannerFactory = MountPlanner
    relay_factory: RelayFactory = HostRelay
    host_access: HostAccess = field(default_factory=detect_host_access)
    log_owner: tuple[int, int] | None = field(default_factory=current_user)


class SandboxSession:
    """Context manager that brings a box up on entry and tears it down on exit."""

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
        self._gateway: RunningGateway | None = None

    @property
    def box(self) -> RunningBox | None:
        return self._box

    @property
    def gateway(self) -> RunningGateway | None:
        return self._gateway

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

    # ---- startup steps ---------------------------------------------------------------

    def _start(self) -> None:
        network_spec = self._spec.network
        policy = NetworkPolicy.parse(network_spec.default, network_spec.allow, network_spec.deny)
        self._observer.building_image(self._spec)
        image_tag = self._services.images.build(self._spec, self._agent)
        gateway_tag = self._services.gateway_images.build()

        self._observer.starting_gateway()
        network = self._create_network()
        relay = self._start_relay(policy, network)
        self._gateway = self._start_gateway(gateway_tag, network)
        if relay is not None and self._gateway.address:
            relay.allow_source(self._gateway.address)

        self._observer.starting_container()
        environment = self._services.environment.build(self._agent)
        box = self._services.boxes.start(
            self._spec,
            self._project_root,
            image_tag,
            self._services.mount_planner_factory(self._project_root).plan(self._spec),
            environment,
            network_container=self._gateway.id,
        )
        self._cleanup.callback(self._services.boxes.stop, box.id)
        self._agent.prepare_container(box.handle, environment)
        self._box = box

    def _create_network(self) -> SandboxNetwork:
        network = self._services.gateways.create_network(self._spec, self._project_root)
        self._cleanup.callback(self._services.gateways.remove_network, network.id)
        return network

    def _start_relay(self, policy: NetworkPolicy, network: SandboxNetwork) -> HostRelay | None:
        if self._services.host_access is not HostAccess.BRIDGE_RELAY:
            return None
        ports = relay_ports(policy)
        if not ports:
            return None
        if network.gateway_address is None:
            raise SandboxError(f"network {network.name} has no gateway address for the relay")
        relay = self._services.relay_factory(network.gateway_address, ports)
        self._cleanup.callback(relay.stop)
        relay.start()
        return relay

    def _start_gateway(self, image_tag: str, network: SandboxNetwork) -> RunningGateway:
        log_dir = audit_log_path(self._project_root).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        relayed = self._services.host_access is HostAccess.BRIDGE_RELAY
        config = GatewayConfig(
            default=self._spec.network.default,
            allow=list(self._spec.network.allow),
            deny=list(self._spec.network.deny),
            host_access=self._services.host_access,
            host_address=network.gateway_address if relayed else None,
            log_owner=self._services.log_owner,
        )
        gateways = self._services.gateways
        gateway = gateways.start(
            self._spec, self._project_root, image_tag, network, config, log_dir
        )
        self._cleanup.callback(gateways.stop, gateway.id)
        gateways.wait_ready(gateway)
        return gateway
