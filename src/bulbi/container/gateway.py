"""The dedicated network and the gateway container that owns a box's network namespace."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bulbi.constants import (
    DOCKER_LABEL,
    DOCKER_LABEL_BOX,
    DOCKER_LABEL_ROLE,
    DOCKER_LABEL_VALUE,
    GATEWAY_ROLE,
)
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.errors import SandboxError
from bulbi.gateway.config import CONFIG_ENV, LOG_MOUNT, READY_DIR, READY_FILE, GatewayConfig
from bulbi.spec import BulbiSpec

READY_TIMEOUT_SECONDS = 10.0
_READY_POLL_SECONDS = 0.2
_NAME_HASH_LENGTH = 8
_STOP_TIMEOUT_SECONDS = 5
_GATEWAY_CAPABILITIES = ["NET_ADMIN", "SETUID", "SETGID"]
_GATEWAY_PIDS_LIMIT = 64
_GATEWAY_MEMORY = "128m"
_LOG_TAIL_LINES = 20


@dataclass(frozen=True)
class SandboxNetwork:
    """A bridge network with the gateway as its only member."""

    id: str
    name: str
    gateway_address: str | None  # The bridge's own address (the host side).


@dataclass(frozen=True)
class RunningGateway:
    id: str
    name: str
    address: str | None  # The gateway container's address on the sandbox network.


def _project_suffix(spec: BulbiSpec, project_root: Path) -> str:
    project_hash = hashlib.sha256(str(project_root).encode()).hexdigest()[:_NAME_HASH_LENGTH]
    return f"{spec.box.name}-{project_hash}"


class GatewayManager:
    """Creates and removes the sandbox network and gateway through an injected Docker client."""

    def __init__(
        self,
        docker_client: Any,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._docker = docker_client
        self._clock = clock
        self._sleep = sleep

    @staticmethod
    def network_name(spec: BulbiSpec, project_root: Path) -> str:
        return f"bulbi-net-{_project_suffix(spec, project_root)}"

    @staticmethod
    def gateway_name(spec: BulbiSpec, project_root: Path) -> str:
        return f"bulbi-gw-{_project_suffix(spec, project_root)}"

    def _labels(self, spec: BulbiSpec) -> dict[str, str]:
        return {
            DOCKER_LABEL: DOCKER_LABEL_VALUE,
            DOCKER_LABEL_BOX: spec.box.name,
            DOCKER_LABEL_ROLE: GATEWAY_ROLE,
        }

    # ---- network -----------------------------------------------------------------

    def create_network(self, spec: BulbiSpec, project_root: Path) -> SandboxNetwork:
        name = self.network_name(spec, project_root)
        with docker_errors(f"failed to create network {name}"):
            self._remove_stale_network(name)
            network = self._docker.networks.create(
                name, driver="bridge", labels=self._labels(spec), check_duplicate=True
            )
            network.reload()
        configs = network.attrs.get("IPAM", {}).get("Config") or [{}]
        return SandboxNetwork(network.id, name, configs[0].get("Gateway"))

    def remove_network(self, network_id: str) -> None:
        with docker_errors(f"failed to remove network {network_id}"):
            try:
                self._docker.networks.get(network_id).remove()
            except docker_sdk().errors.NotFound:
                return

    def _remove_stale_network(self, name: str) -> None:
        for network in self._docker.networks.list(names=[name]):
            if network.name == name:
                with suppress(docker_sdk().errors.APIError):
                    network.remove()

    # ---- gateway container --------------------------------------------------------

    def start(
        self,
        spec: BulbiSpec,
        project_root: Path,
        image_tag: str,
        network: SandboxNetwork,
        config: GatewayConfig,
        log_dir: Path,
    ) -> RunningGateway:
        name = self.gateway_name(spec, project_root)
        with docker_errors(f"failed to start gateway {name}"):
            with suppress(docker_sdk().errors.NotFound):
                self._docker.containers.get(name).remove(force=True)
            container = self._docker.containers.run(
                image_tag,
                detach=True,
                name=name,
                labels=self._labels(spec),
                network=network.name,
                environment={CONFIG_ENV: config.to_json()},
                mounts=[
                    docker_sdk().types.Mount(
                        target=LOG_MOUNT, source=str(log_dir), type="bind", read_only=False
                    )
                ],
                cap_drop=["ALL"],
                cap_add=list(_GATEWAY_CAPABILITIES),
                security_opt=["no-new-privileges"],
                read_only=True,
                tmpfs={READY_DIR: "size=64k"},
                pids_limit=_GATEWAY_PIDS_LIMIT,
                mem_limit=_GATEWAY_MEMORY,
                init=True,
            )
            container.reload()
        address = (
            container.attrs.get("NetworkSettings", {})
            .get("Networks", {})
            .get(network.name, {})
            .get("IPAddress")
        )
        return RunningGateway(container.id, name, address or None)

    def wait_ready(self, gateway: RunningGateway, timeout: float = READY_TIMEOUT_SECONDS) -> None:
        """Block until the gateway has loaded its rules, or raise SandboxError."""
        deadline = self._clock() + timeout
        with docker_errors(f"failed to check gateway {gateway.name}"):
            container = self._docker.containers.get(gateway.id)
            while True:
                container.reload()
                if container.status in {"exited", "dead"}:
                    raise SandboxError(
                        f"gateway {gateway.name} exited during startup:\n{self._logs(container)}"
                    )
                if container.exec_run(["cat", READY_FILE]).exit_code == 0:
                    return
                if self._clock() >= deadline:
                    raise SandboxError(
                        f"gateway {gateway.name} did not become ready within {timeout:.0f}s:\n"
                        f"{self._logs(container)}"
                    )
                self._sleep(_READY_POLL_SECONDS)

    def stop(self, gateway_id: str) -> None:
        with docker_errors(f"failed to stop gateway {gateway_id}"):
            try:
                container = self._docker.containers.get(gateway_id)
            except docker_sdk().errors.NotFound:
                return
            container.stop(timeout=_STOP_TIMEOUT_SECONDS)
            container.remove(force=True)

    @staticmethod
    def _logs(container: Any) -> str:
        with suppress(docker_sdk().errors.APIError):
            raw: bytes = container.logs(tail=_LOG_TAIL_LINES)
            return raw.decode(errors="replace").strip()
        return "(no logs)"
