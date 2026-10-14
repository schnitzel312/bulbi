"""One box (plus one gateway) per project and profile, shared by every session (spec §8).

:meth:`BoxOrchestrator.ensure` takes the project's lock, observes what exists, lets
:class:`BoxPlanner` choose attach / start / recreate / create, applies it, and returns
the running box. :meth:`release` runs when a session ends and stops the box and gateway
when nobody is left and ``idle_timeout`` is ``0``.
"""

from __future__ import annotations

import glob
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from bulbi.agents import Agent, BoxContext
from bulbi.container.gateway import GatewayManager, RunningGateway, SandboxNetwork
from bulbi.container.identity import BoxIdentity
from bulbi.container.manager import BoxLaunch, BoxManager, ContainerState, RunningBox
from bulbi.container.mounts import PROJECT_MOUNT_PATH, MountPlanner
from bulbi.container.sessions import SessionTracker
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.gateway.audit import audit_log_path
from bulbi.gateway.config import GatewayConfig, HostAccess
from bulbi.gateway.policy import NetworkPolicy
from bulbi.gateway.relay import relay_ports
from bulbi.image import ImageBuilder
from bulbi.image.entrypoint import ATTACH_MARKER_PATH
from bulbi.image.gateway import GatewayImageBuilder
from bulbi.project.locator import Project
from bulbi.sandbox.hashing import SpecHasher
from bulbi.sandbox.lock import LOCK_FILENAME, BoxLock, FileBoxLock
from bulbi.sandbox.observer import SandboxObserver
from bulbi.sandbox.planner import BoxObservation, BoxPlan, BoxPlanner
from bulbi.sandbox.relay import ProcessRelayLauncher, RelayLauncher
from bulbi.secrets import (
    ResolvedSecret,
    SecretDeliveries,
    SecretPlan,
    SecretReaders,
    user_declarations,
)
from bulbi.spec import BulbiSpec

MountPlannerFactory = Callable[[Project], MountPlanner]
LockFactory = Callable[[Path], BoxLock]
RelayLauncherFactory = Callable[[Path], RelayLauncher]


def file_lock(state_dir: Path) -> BoxLock:
    return FileBoxLock(state_dir / LOCK_FILENAME)


@dataclass(frozen=True)
class SandboxServices:
    """The collaborators the orchestrator uses to talk to Docker and the host."""

    images: ImageBuilder
    gateway_images: GatewayImageBuilder
    boxes: BoxManager
    gateways: GatewayManager
    sessions: SessionTracker
    terminal: TerminalExec
    secret_readers: SecretReaders = field(default_factory=SecretReaders.builtin)
    secret_deliveries: SecretDeliveries = field(default_factory=SecretDeliveries.builtin)
    mount_planner_factory: MountPlannerFactory = MountPlanner
    lock_factory: LockFactory = file_lock
    relay_launcher_factory: RelayLauncherFactory = ProcessRelayLauncher
    host_access: HostAccess = HostAccess.DOCKER_DESKTOP
    log_owner: tuple[int, int] | None = None
    planner: BoxPlanner = field(default_factory=BoxPlanner)
    hasher: SpecHasher = field(default_factory=SpecHasher)


class BoxOrchestrator:
    """Finds, starts, shares and stops the box for one project and profile."""

    def __init__(
        self,
        spec: BulbiSpec,
        project: Project,
        agent: Agent,
        services: SandboxServices,
        observer: SandboxObserver | None = None,
        profile: str | None = None,
    ) -> None:
        self._spec = spec
        self._project = project
        self._agent = agent
        self._services = services
        self._observer = observer or SandboxObserver()
        self.identity = BoxIdentity(project.key, spec.box.name, profile)
        self._planner = services.mount_planner_factory(project)
        self._secrets: list[ResolvedSecret] = []

    @property
    def secret_plan(self) -> SecretPlan:
        """The agent's built-in secrets, overridden by the spec's [secrets] (spec §10.2)."""
        return SecretPlan(self._agent.secrets, user_declarations(self._spec.secrets))

    def session_environment(self) -> dict[str, str]:
        """Secret env vars for one session, as resolved by the last :meth:`ensure`."""
        return self._services.secret_deliveries.session_environment(self._secrets)

    @property
    def workdir(self) -> Path:
        """Where sessions start: the directory the CLI was started from."""
        return self._project.cwd

    @property
    def state_dir(self) -> Path:
        """``.bulbi/`` in the main checkout: lock, audit log, relay state."""
        return audit_log_path(self._project.root).parent

    @property
    def context(self) -> BoxContext:
        dirs = dict.fromkeys(
            str(path)
            for path in (*self._planner.checkout_roots(self._spec), *self._project.worktrees)
        )
        return BoxContext(dict(self._agent.environment), tuple(dirs))

    # ---- sessions ----------------------------------------------------------------------

    def ensure(self) -> RunningBox:
        """The running, current box for this project, created or started as needed."""
        network = self._spec.network
        policy = NetworkPolicy.parse(network.default, network.allow, network.deny)
        self._spec.box.idle_timeout_seconds()  # Fail early on a malformed timeout.
        # Read secrets on the host first: a missing one stops the run before anything starts.
        self._secrets = self.secret_plan.resolve(self._services.secret_readers)
        self._observer.building_image(self._spec)
        box_image = self._services.images.build(self._spec, self._agent)
        gateway_image = self._services.gateway_images.build()
        spec_hash = self._services.hasher.hash(
            self._spec, box_image, gateway_image, self._planner.checkout_roots(self._spec)
        )
        with self._services.lock_factory(self.state_dir).hold():
            self._services.gateways.reap(self._services.boxes.list_containers())
            observation = self._observe()
            plan = self._services.planner.plan(observation, spec_hash)
            box = self._apply(plan, observation, policy, box_image, gateway_image, spec_hash)
            # Under the lock: tell the idle watcher a session is about to attach.
            box.handle.exec(["touch", ATTACH_MARKER_PATH])
            self._check_late_worktree(plan)
            # Files are (re)written on every attach so rotated values are picked up.
            self._services.secret_deliveries.write_files(self._secrets, box.handle)
            return box

    def release(self) -> None:
        """After a session ends: with nobody left and ``idle_timeout = 0``, stop everything."""
        with self._services.lock_factory(self.state_dir).hold():
            box = self._services.boxes.find(self.identity.name)
            if box is None or self._services.sessions.active_sessions(box.id):
                return
            if self._spec.box.idle_timeout_seconds() == 0:
                self._stop(box)

    def active_sessions(self) -> int:
        box = self._services.boxes.find(self.identity.name)
        return self._services.sessions.active_sessions(box.id) if box and box.running else 0

    def stop(self) -> bool:
        """Stop this project's box and gateway (kept for a fast restart); False if none."""
        with self._services.lock_factory(self.state_dir).hold():
            box = self._services.boxes.find(self.identity.name)
            if box is None:
                return False
            self._stop(box)
            return True

    def recreate(self) -> RunningBox:
        """Throw the box away and build it again from the current spec (``bulbi restart``)."""
        with self._services.lock_factory(self.state_dir).hold():
            self._remove_all()
        return self.ensure()

    # ---- plans -------------------------------------------------------------------------

    def _observe(self) -> BoxObservation:
        box = self._services.boxes.find(self.identity.name)
        gateway = self._services.gateways.find(self.identity)
        sessions = (
            self._services.sessions.active_sessions(box.id)
            if box is not None and box.running
            else 0
        )
        return BoxObservation(box, gateway, sessions)

    def _apply(
        self,
        plan: BoxPlan,
        observation: BoxObservation,
        policy: NetworkPolicy,
        box_image: str,
        gateway_image: str,
        spec_hash: str,
    ) -> RunningBox:
        if plan is BoxPlan.ATTACH:
            assert observation.box is not None
            box = self._services.boxes.attach(observation.box.id)
            self._ensure_relay(policy)
            self._agent.refresh(box.handle, self.context)
            return box
        if plan is BoxPlan.START:
            assert observation.box is not None and observation.gateway is not None
            return self._start_existing(observation.box, observation.gateway, policy)
        if plan is BoxPlan.RECREATE:
            self._remove_all()
        return self._create(policy, box_image, gateway_image, spec_hash)

    def _create(
        self, policy: NetworkPolicy, box_image: str, gateway_image: str, spec_hash: str
    ) -> RunningBox:
        """The full start sequence (spec §4), rolled back if any step fails."""
        services = self._services
        with ExitStack() as rollback:
            self._observer.starting_gateway()
            network = services.gateways.create_network(self.identity)
            rollback.callback(services.gateways.remove_network, network.id)
            gateway = self._start_gateway(gateway_image, network, spec_hash)
            rollback.callback(services.gateways.remove, gateway.id)
            relay = self._start_relay(policy, network, gateway)
            if relay is not None:
                rollback.callback(relay.stop)
            self._observer.starting_container()
            context = self.context
            box = services.boxes.create(
                BoxLaunch(
                    identity=self.identity,
                    spec=self._spec,
                    image_tag=box_image,
                    spec_hash=spec_hash,
                    mounts=self._planner.plan(self._spec),
                    environment=context.environment,
                    gateway_id=gateway.id,
                    project_root=self._project.root,
                    worktrees=self._project.worktrees or (self._project.root,),
                )
            )
            rollback.callback(services.boxes.remove, box.id)
            self._agent.prepare_container(box.handle, context)
            rollback.pop_all()
        return box

    def _start_existing(
        self, box: ContainerState, gateway: ContainerState, policy: NetworkPolicy
    ) -> RunningBox:
        """Stopped box, same spec: gateway first, then the box, then prepare again."""
        services = self._services
        network = services.gateways.find_network(self.identity)
        if network is None:
            raise SandboxError(
                f"network {self.identity.network_name} is missing; run `bulbi restart`"
            )
        self._observer.starting_gateway()
        services.boxes.stop(box.id)
        running_gateway = services.gateways.ensure_running(gateway, network.name)
        services.gateways.wait_ready(running_gateway)
        self._start_relay(policy, network, running_gateway)
        self._observer.starting_container()
        started = services.boxes.start(box.id)
        self._agent.prepare_container(started.handle, self.context)
        return started

    def _start_gateway(
        self, image: str, network: SandboxNetwork, spec_hash: str
    ) -> RunningGateway:
        self.state_dir.mkdir(parents=True, exist_ok=True)
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
        gateway = gateways.start(self.identity, spec_hash, image, network, config, self.state_dir)
        try:
            gateways.wait_ready(gateway)
        except BaseException:
            gateways.remove(gateway.id)
            raise
        return gateway

    def _start_relay(
        self, policy: NetworkPolicy, network: SandboxNetwork, gateway: RunningGateway
    ) -> RelayLauncher | None:
        if self._services.host_access is not HostAccess.BRIDGE_RELAY:
            return None
        ports = relay_ports(policy)
        if not ports:
            return None
        if network.gateway_address is None or gateway.address is None:
            raise SandboxError(f"network {network.name} has no addresses for the host relay")
        relay = self._services.relay_launcher_factory(self.state_dir)
        relay.ensure(network.gateway_address, ports, gateway.address)
        return relay

    def _ensure_relay(self, policy: NetworkPolicy) -> None:
        """When attaching: restart the host relay if it died (e.g. after a host reboot)."""
        if self._services.host_access is not HostAccess.BRIDGE_RELAY or not relay_ports(policy):
            return
        network = self._services.gateways.find_network(self.identity)
        gateway = self._services.gateways.find(self.identity)
        if network is not None and gateway is not None:
            running = self._services.gateways.ensure_running(gateway, network.name)
            self._start_relay(policy, network, running)

    def _stop(self, box: ContainerState) -> None:
        self._services.boxes.stop(box.id)
        gateway = self._services.gateways.find(self.identity)
        if gateway is not None:
            self._services.gateways.stop(gateway.id)
        self._services.relay_launcher_factory(self.state_dir).stop()

    def _remove_all(self) -> None:
        box = self._services.boxes.find(self.identity.name)
        if box is not None:
            self._services.boxes.remove(box.id)
        gateway = self._services.gateways.find(self.identity)
        if gateway is not None:
            self._services.gateways.remove(gateway.id)
        network = self._services.gateways.find_network(self.identity)
        if network is not None:
            self._services.gateways.remove_network(network.id)
        self._services.relay_launcher_factory(self.state_dir).stop()

    # ---- late worktrees (spec §9.4) ----------------------------------------------------

    def _check_late_worktree(self, plan: BoxPlan) -> None:
        """Refuse a session from a checkout the running box cannot fully protect."""
        if plan not in (BoxPlan.ATTACH, BoxPlan.START):
            return
        box = self._services.boxes.find(self.identity.name)
        current = self._project.current
        if box is None or str(current) in box.worktrees_at_start:
            return
        covered = any(
            current == Path(target) or Path(target) in current.parents
            for target in box.mount_targets
        )
        if not covered:
            raise SandboxError(
                f"{current} is not mounted in the running box; run `bulbi restart` "
                "when the other sessions finish"
            )
        if self._has_excluded_files(current):
            raise SandboxError(
                "this worktree has excluded files that the running box can't hide; "
                "run `bulbi restart` when the other sessions finish"
            )

    def _has_excluded_files(self, checkout: Path) -> bool:
        patterns = [
            pattern
            for mount in self._spec.mounts
            if mount.path == PROJECT_MOUNT_PATH
            for pattern in mount.exclude
        ]
        return any(glob.glob(str(checkout / pattern)) for pattern in patterns)
