"""Lifecycle of box containers through an injected Docker client."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulbi.agents.ports import ContainerHandle
from bulbi.constants import (
    DOCKER_LABEL,
    DOCKER_LABEL_PROJECT,
    DOCKER_LABEL_ROLE,
    DOCKER_LABEL_SPEC_HASH,
    DOCKER_LABEL_VALUE,
    GATEWAY_ROLE,
)
from bulbi.container.handle import DockerContainerHandle
from bulbi.container.identity import GATEWAY_SUFFIX, NETWORK_SUFFIX, BoxIdentity
from bulbi.container.mounts import BindMount, PlannedMount, TmpfsMount, VolumeMount
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.image.entrypoint import IDLE_WATCHER_PATH, PROJECT_DIR_ENV
from bulbi.spec import BulbiSpec, LimitsSpec

_STOP_TIMEOUT_SECONDS = 10
_NANO_CPUS_PER_CPU = 10**9
BOX_PIDS_LIMIT = 512
WORKTREES_LABEL = "bulbi.worktrees"
RUNNING = "running"
_BULBI_FILTER = {"label": f"{DOCKER_LABEL}={DOCKER_LABEL_VALUE}"}


@dataclass(frozen=True)
class RunningBox:
    """A started box: its container ID and a handle for working inside it."""

    id: str
    handle: ContainerHandle


@dataclass(frozen=True)
class ContainerState:
    """A Bulbi container (box or gateway) as Docker reports it."""

    id: str
    name: str
    status: str
    labels: Mapping[str, str] = field(default_factory=dict)
    started_at: str | None = None
    mount_targets: frozenset[str] = frozenset()

    @property
    def running(self) -> bool:
        return self.status == RUNNING

    @property
    def spec_hash(self) -> str | None:
        return self.labels.get(DOCKER_LABEL_SPEC_HASH)

    @property
    def is_gateway(self) -> bool:
        return self.labels.get(DOCKER_LABEL_ROLE) == GATEWAY_ROLE

    @property
    def worktrees_at_start(self) -> list[str]:
        """Checkouts that existed (and had their excludes masked) when the box was created."""
        try:
            value = json.loads(self.labels.get(WORKTREES_LABEL, "[]"))
        except ValueError:
            return []
        return [str(item) for item in value] if isinstance(value, list) else []

    @classmethod
    def of(cls, container: Any) -> ContainerState:
        attrs = container.attrs or {}
        mounts = attrs.get("Mounts") or []
        return cls(
            id=container.id,
            name=container.name,
            status=container.status,
            labels=dict(container.labels or {}),
            started_at=(attrs.get("State") or {}).get("StartedAt"),
            mount_targets=frozenset(m.get("Destination", "") for m in mounts),
        )


@dataclass(frozen=True)
class BoxLaunch:
    """Everything needed to create a box container."""

    identity: BoxIdentity
    spec: BulbiSpec
    image_tag: str
    spec_hash: str
    mounts: Sequence[PlannedMount]
    environment: Mapping[str, str]
    gateway_id: str
    project_root: Path
    worktrees: Sequence[Path] = ()


class BoxManager:
    """Creates, starts, stops, lists and removes box containers."""

    def __init__(self, docker_client: Any) -> None:
        self._docker = docker_client

    def find(self, name: str) -> ContainerState | None:
        with docker_errors(f"failed to inspect container {name}"):
            try:
                return ContainerState.of(self._docker.containers.get(name))
            except docker_sdk().errors.NotFound:
                return None

    def create(self, launch: BoxLaunch) -> RunningBox:
        """Create and start a hardened box inside the gateway's network namespace.

        Its PID 1 is the idle watcher, so the box stops itself after ``idle_timeout``
        without sessions; commands run separately with ``docker exec``.
        """
        name = launch.identity.name
        labels = {
            **launch.identity.labels(launch.spec_hash),
            WORKTREES_LABEL: json.dumps([str(path) for path in launch.worktrees]),
        }
        with docker_errors(f"failed to start container {name}"):
            with suppress(docker_sdk().errors.NotFound):
                self._docker.containers.get(name).remove(force=True)
            container = self._docker.containers.run(
                launch.image_tag,
                command=[IDLE_WATCHER_PATH, str(launch.spec.box.idle_timeout_seconds())],
                entrypoint=[],
                detach=True,
                name=name,
                labels=labels,
                mounts=[self.to_docker_mount(mount) for mount in launch.mounts],
                environment={**launch.environment, PROJECT_DIR_ENV: str(launch.project_root)},
                stdin_open=True,
                tty=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                pids_limit=BOX_PIDS_LIMIT,
                network_mode=f"container:{launch.gateway_id}",
                **self._resource_limits(launch.spec.limits),
            )
        return RunningBox(id=container.id, handle=DockerContainerHandle(container))

    def start(self, container_id: str) -> RunningBox:
        """Start a stopped box again; its filesystem (setup state) is preserved."""
        with docker_errors(f"failed to start container {container_id}"):
            container = self._docker.containers.get(container_id)
            container.start()
        return RunningBox(id=container.id, handle=DockerContainerHandle(container))

    def attach(self, container_id: str) -> RunningBox:
        with docker_errors(f"failed to inspect container {container_id}"):
            container = self._docker.containers.get(container_id)
        return RunningBox(id=container.id, handle=DockerContainerHandle(container))

    def stop(self, container_id: str) -> None:
        """Stop a container but keep it, so the next start is fast (spec §8.3)."""
        with docker_errors(f"failed to stop container {container_id}"):
            try:
                container = self._docker.containers.get(container_id)
            except docker_sdk().errors.NotFound:
                return
            if container.status == RUNNING:
                container.stop(timeout=_STOP_TIMEOUT_SECONDS)

    def remove(self, container_id: str) -> None:
        with docker_errors(f"failed to remove container {container_id}"):
            try:
                self._docker.containers.get(container_id).remove(force=True)
            except docker_sdk().errors.NotFound:
                return

    def list_containers(self) -> list[ContainerState]:
        """Every Bulbi container: boxes and gateways."""
        with docker_errors("failed to list containers"):
            containers = self._docker.containers.list(all=True, filters=_BULBI_FILTER)
            return [ContainerState.of(container) for container in containers]

    def list_boxes(self) -> list[ContainerState]:
        """Bulbi boxes; gateways are infrastructure and stay hidden."""
        return [state for state in self.list_containers() if not state.is_gateway]

    def remove_box(self, name_or_id: str) -> None:
        """Remove a box together with its gateway and network (``bulbi rm``)."""
        with docker_errors(f"failed to remove container {name_or_id}"):
            container = self._docker.containers.get(name_or_id)
            state = ContainerState.of(container)
            container.remove(force=True)
            if state.is_gateway or DOCKER_LABEL_PROJECT not in state.labels:
                return
            with suppress(docker_sdk().errors.NotFound):
                self._docker.containers.get(state.name + GATEWAY_SUFFIX).remove(force=True)
            with suppress(docker_sdk().errors.NotFound, docker_sdk().errors.APIError):
                self._docker.networks.get(state.name + NETWORK_SUFFIX).remove()

    def reset(self) -> None:
        """Remove every Bulbi box, gateway, network and image (boxes before gateways)."""
        with docker_errors("failed to reset"):
            containers = self._docker.containers.list(all=True, filters=_BULBI_FILTER)
            containers.sort(key=lambda c: c.labels.get(DOCKER_LABEL_ROLE) == GATEWAY_ROLE)
            for container in containers:
                container.remove(force=True)
            for network in self._docker.networks.list(filters=_BULBI_FILTER):
                network.remove()
            for image in self._docker.images.list(filters=_BULBI_FILTER):
                self._docker.images.remove(image.id, force=True)

    @staticmethod
    def _resource_limits(limits: LimitsSpec) -> dict[str, int]:
        return {
            "nano_cpus": limits.cpu * _NANO_CPUS_PER_CPU,
            "mem_limit": limits.memory_bytes(),
        }

    @staticmethod
    def to_docker_mount(mount: PlannedMount) -> Any:
        mount_type = docker_sdk().types.Mount
        if isinstance(mount, TmpfsMount):
            return mount_type(target=mount.target, source=None, type="tmpfs", read_only=True)
        if isinstance(mount, VolumeMount):
            return mount_type(
                target=mount.target, source=mount.volume, type="volume", read_only=mount.read_only
            )
        assert isinstance(mount, BindMount)
        return mount_type(
            target=mount.target, source=mount.source, type="bind", read_only=mount.read_only
        )
