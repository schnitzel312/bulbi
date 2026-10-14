"""Lifecycle of box containers through an injected Docker client."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bulbi.agents.ports import ContainerHandle
from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_BOX, DOCKER_LABEL_VALUE
from bulbi.container.handle import DockerContainerHandle
from bulbi.container.mounts import BindMount
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.spec import BulbiSpec, LimitsSpec

_NAME_HASH_LENGTH = 8
_STOP_TIMEOUT_SECONDS = 10
_NANO_CPUS_PER_CPU = 10**9
# Keeps the container alive; commands are run separately with `docker exec`.
_IDLE_COMMAND = ["sleep", "infinity"]
_BULBI_FILTER = {"label": f"{DOCKER_LABEL}={DOCKER_LABEL_VALUE}"}


@dataclass(frozen=True)
class RunningBox:
    """A started box: its container ID and a handle for working inside it."""

    id: str
    handle: ContainerHandle


@dataclass(frozen=True)
class BoxInfo:
    """Summary of a Bulbi-managed container, for ``bulbi ls``."""

    id: str
    name: str
    box: str
    status: str


class BoxManager:
    """Creates, stops, lists, and removes Bulbi containers."""

    def __init__(self, docker_client: Any) -> None:
        self._docker = docker_client

    @staticmethod
    def container_name(spec: BulbiSpec, project_root: Path) -> str:
        """Stable per project, so a new run replaces the previous run's container."""
        project_hash = hashlib.sha256(str(project_root).encode()).hexdigest()
        return f"bulbi-{spec.box.name}-{project_hash[:_NAME_HASH_LENGTH]}"

    def start(
        self,
        spec: BulbiSpec,
        project_root: Path,
        image_tag: str,
        mounts: list[BindMount],
        environment: Mapping[str, str],
    ) -> RunningBox:
        """Start an idle container for the box, replacing any stale one."""
        name = self.container_name(spec, project_root)
        with docker_errors(f"failed to start container {name}"):
            self._remove_if_present(name)
            container = self._docker.containers.run(
                image_tag,
                command=_IDLE_COMMAND,
                entrypoint=[],
                detach=True,
                name=name,
                labels={DOCKER_LABEL: DOCKER_LABEL_VALUE, DOCKER_LABEL_BOX: spec.box.name},
                mounts=[self._to_docker_mount(mount) for mount in mounts],
                environment=dict(environment),
                stdin_open=True,
                tty=True,
                **self._resource_limits(spec.limits),
            )
        return RunningBox(id=container.id, handle=DockerContainerHandle(container))

    def stop(self, container_id: str) -> None:
        """Stop and remove a container; a container that is already gone is fine."""
        with docker_errors(f"failed to stop container {container_id}"):
            try:
                container = self._docker.containers.get(container_id)
            except docker_sdk().errors.NotFound:
                return
            container.stop(timeout=_STOP_TIMEOUT_SECONDS)
            container.remove()

    def list_boxes(self) -> list[BoxInfo]:
        with docker_errors("failed to list containers"):
            containers = self._docker.containers.list(all=True, filters=_BULBI_FILTER)
            return [
                BoxInfo(
                    id=container.short_id,
                    name=container.name,
                    box=container.labels.get(DOCKER_LABEL_BOX, ""),
                    status=container.status,
                )
                for container in containers
            ]

    def remove(self, name_or_id: str) -> None:
        with docker_errors(f"failed to remove container {name_or_id}"):
            self._docker.containers.get(name_or_id).remove(force=True)

    def reset(self) -> None:
        """Remove every Bulbi container and image."""
        with docker_errors("failed to reset"):
            for container in self._docker.containers.list(all=True, filters=_BULBI_FILTER):
                container.remove(force=True)
            for image in self._docker.images.list(filters=_BULBI_FILTER):
                self._docker.images.remove(image.id, force=True)

    def _remove_if_present(self, name: str) -> None:
        with suppress(docker_sdk().errors.NotFound):
            self._docker.containers.get(name).remove(force=True)

    @staticmethod
    def _resource_limits(limits: LimitsSpec) -> dict[str, int]:
        return {
            "nano_cpus": limits.cpu * _NANO_CPUS_PER_CPU,
            "mem_limit": limits.memory_bytes(),
        }

    @staticmethod
    def _to_docker_mount(mount: BindMount) -> Any:
        return docker_sdk().types.Mount(
            target=mount.target, source=mount.source, type="bind", read_only=mount.read_only
        )
