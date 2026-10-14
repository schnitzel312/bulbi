"""The dedicated network and the gateway container that owns a box's network namespace."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bulbi.container.identity import GATEWAY_SUFFIX, BoxIdentity
from bulbi.container.manager import RUNNING, ContainerState
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.errors import SandboxError
from bulbi.gateway.config import CONFIG_ENV, LOG_MOUNT, READY_DIR, READY_FILE, GatewayConfig

READY_TIMEOUT_SECONDS = 10.0
_READY_POLL_SECONDS = 0.2
_STOP_TIMEOUT_SECONDS = 5
_GATEWAY_CAPABILITIES = ["NET_ADMIN", "SETUID", "SETGID"]
_GATEWAY_PIDS_LIMIT = 64
_GATEWAY_MEMORY = "128m"
_LOG_TAIL_LINES = 20
_NETWORK_REMOVE_ATTEMPTS = 5
_NETWORK_REMOVE_RETRY_SECONDS = 0.5


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

    # ---- network -----------------------------------------------------------------

    def find(self, identity: BoxIdentity) -> ContainerState | None:
        with docker_errors(f"failed to inspect gateway {identity.gateway_name}"):
            try:
                return ContainerState.of(self._docker.containers.get(identity.gateway_name))
            except docker_sdk().errors.NotFound:
                return None

    def find_network(self, identity: BoxIdentity) -> SandboxNetwork | None:
        with docker_errors(f"failed to inspect network {identity.network_name}"):
            try:
                network = self._docker.networks.get(identity.network_name)
            except docker_sdk().errors.NotFound:
                return None
        return self._network_of(network)

    def create_network(self, identity: BoxIdentity) -> SandboxNetwork:
        name = identity.network_name
        with docker_errors(f"failed to create network {name}"):
            self._remove_stale_network(name)
            network = self._docker.networks.create(
                name, driver="bridge", labels=identity.labels(), check_duplicate=True
            )
            network.reload()
        return self._network_of(network)

    @staticmethod
    def _network_of(network: Any) -> SandboxNetwork:
        configs = network.attrs.get("IPAM", {}).get("Config") or [{}]
        return SandboxNetwork(network.id, network.name, configs[0].get("Gateway"))

    def remove_network(self, network_id: str) -> None:
        """Remove the network, retrying while a just-removed gateway's endpoint detaches."""
        errors = docker_sdk().errors
        with docker_errors(f"failed to remove network {network_id}"):
            for attempt in range(_NETWORK_REMOVE_ATTEMPTS):
                try:
                    self._docker.networks.get(network_id).remove()
                    return
                except errors.NotFound:
                    return
                except errors.APIError:
                    if attempt == _NETWORK_REMOVE_ATTEMPTS - 1:
                        raise
                    self._sleep(_NETWORK_REMOVE_RETRY_SECONDS)

    def _remove_stale_network(self, name: str) -> None:
        for network in self._docker.networks.list(names=[name]):
            if network.name == name:
                with suppress(docker_sdk().errors.APIError):
                    network.remove()

    # ---- gateway container --------------------------------------------------------

    def start(
        self,
        identity: BoxIdentity,
        spec_hash: str,
        image_tag: str,
        network: SandboxNetwork,
        config: GatewayConfig,
        log_dir: Path,
    ) -> RunningGateway:
        name = identity.gateway_name
        with docker_errors(f"failed to start gateway {name}"):
            with suppress(docker_sdk().errors.NotFound):
                self._docker.containers.get(name).remove(force=True)
            container = self._docker.containers.run(
                image_tag,
                detach=True,
                name=name,
                labels=identity.labels(spec_hash, gateway=True),
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
        return self._running(container, network.name)

    def ensure_running(self, gateway: ContainerState, network_name: str) -> RunningGateway:
        """The gateway, started again if it was stopped (it reloads its rules on start)."""
        with docker_errors(f"failed to start gateway {gateway.name}"):
            container = self._docker.containers.get(gateway.id)
            if container.status != RUNNING:
                container.start()
            container.reload()
        return self._running(container, network_name)

    @staticmethod
    def _running(container: Any, network_name: str) -> RunningGateway:
        address = (
            container.attrs.get("NetworkSettings", {})
            .get("Networks", {})
            .get(network_name, {})
            .get("IPAddress")
        )
        return RunningGateway(container.id, container.name, address or None)

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
        """Stop the gateway but keep it, so the box can be started again quickly."""
        with docker_errors(f"failed to stop gateway {gateway_id}"):
            try:
                container = self._docker.containers.get(gateway_id)
            except docker_sdk().errors.NotFound:
                return
            if container.status == RUNNING:
                container.stop(timeout=_STOP_TIMEOUT_SECONDS)

    def remove(self, gateway_id: str) -> None:
        with docker_errors(f"failed to remove gateway {gateway_id}"):
            try:
                self._docker.containers.get(gateway_id).remove(force=True)
            except docker_sdk().errors.NotFound:
                return

    def reap(self, containers: Iterable[ContainerState]) -> list[str]:
        """Stop running gateways whose box is not running (spec §8.3); returns their names."""
        states = list(containers)
        running_boxes = {s.name for s in states if not s.is_gateway and s.running}
        reaped = []
        for state in states:
            box_name = state.name.removesuffix(GATEWAY_SUFFIX)
            if state.is_gateway and state.running and box_name not in running_boxes:
                self.stop(state.id)
                reaped.append(state.name)
        return reaped

    @staticmethod
    def _logs(container: Any) -> str:
        with suppress(docker_sdk().errors.APIError):
            raw: bytes = container.logs(tail=_LOG_TAIL_LINES)
            return raw.decode(errors="replace").strip()
        return "(no logs)"
