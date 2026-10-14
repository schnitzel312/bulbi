"""Test doubles shared across test modules (no real Docker, keychain, or network)."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import docker.errors

from bulbi.agents import ContainerHandle, CredentialProvider, ExecResult
from bulbi.proxy import NetworkProxy
from bulbi.spec import NetworkSpec


class FakeContainerHandle(ContainerHandle):
    """Records commands and keeps written files in memory."""

    def __init__(self, responses: dict[tuple[str, ...], ExecResult] | None = None) -> None:
        self.commands: list[list[str]] = []
        self.files: dict[str, str] = {}
        self.modes: dict[str, int] = {}
        self._responses = responses or {}

    def exec(self, argv: Sequence[str]) -> ExecResult:
        self.commands.append(list(argv))
        return self._responses.get(tuple(argv), ExecResult(exit_code=0, output=""))

    def write_file(self, path: str, content: str, *, mode: int = 0o644) -> None:
        self.files[path] = content
        self.modes[path] = mode


class StaticCredentials(CredentialProvider):
    def __init__(self, value: str | None) -> None:
        self.value = value
        self.reads = 0

    def read(self) -> str | None:
        self.reads += 1
        return self.value


# ---- Docker SDK fakes ---------------------------------------------------------


class FakeExecRun:
    def __init__(self, exit_code: int = 0, output: bytes = b"") -> None:
        self.exit_code = exit_code
        self.output = output


class FakeContainer:
    def __init__(self, name: str, labels: dict[str, str] | None = None) -> None:
        self.id = f"id-{name}"
        self.short_id = self.id[:6]
        self.name = name
        self.status = "running"
        self.labels = labels or {}
        self.exec_calls: list[tuple[list[str], str]] = []
        self.exec_responses: dict[tuple[str, ...], FakeExecRun] = {
            ("id", "-u"): FakeExecRun(0, b"1000\n"),
            ("id", "-g"): FakeExecRun(0, b"1000\n"),
        }
        self.archives: list[tuple[str, bytes]] = []
        self.stopped = False
        self.removed = False
        self.attrs: dict = {"NetworkSettings": {"Networks": {}}}
        self.log_output = b""

    def reload(self) -> None:
        pass

    def logs(self, tail: int) -> bytes:
        return self.log_output

    def exec_run(self, argv: list[str], user: str | None = None) -> FakeExecRun:
        self.exec_calls.append((argv, user))
        return self.exec_responses.get(tuple(argv), FakeExecRun())

    def put_archive(self, path: str, data: bytes) -> bool:
        self.archives.append((path, data))
        return True

    def stop(self, timeout: int) -> None:
        self.stopped = True

    def remove(self, force: bool = False) -> None:
        self.removed = True


class FakeContainers:
    def __init__(self) -> None:
        self.by_key: dict[str, FakeContainer] = {}
        self.run_calls: list[tuple[str, dict]] = []

    def add(self, container: FakeContainer) -> FakeContainer:
        self.by_key[container.name] = self.by_key[container.id] = container
        return container

    def run(self, image: str, **kwargs) -> FakeContainer:
        self.run_calls.append((image, kwargs))
        container = FakeContainer(kwargs["name"], kwargs.get("labels"))
        if "network" in kwargs:
            container.attrs["NetworkSettings"]["Networks"][kwargs["network"]] = {
                "IPAddress": FakeNetworks.GATEWAY_CONTAINER_ADDRESS
            }
        return self.add(container)

    def get(self, key: str) -> FakeContainer:
        container = self.by_key.get(key)
        if container is None or container.removed:
            raise docker.errors.NotFound(f"No such container: {key}")
        return container

    def list(self, all: bool, filters: dict) -> list[FakeContainer]:
        unique = {id(c): c for c in self.by_key.values() if not c.removed}
        return list(unique.values())


class FakeImage:
    def __init__(self, image_id: str) -> None:
        self.id = image_id


class FakeImages:
    def __init__(self, existing: set[str] | None = None) -> None:
        self.tags = set(existing or ())
        self.builds: list[dict] = []
        self.removed: list[str] = []

    def get(self, tag: str) -> FakeImage:
        if tag not in self.tags:
            raise docker.errors.ImageNotFound(f"No such image: {tag}")
        return FakeImage(tag)

    def build(self, fileobj, tag: str, labels: dict, rm: bool, custom_context=False) -> None:
        data = fileobj.read()
        dockerfile = None if custom_context else data.decode()
        self.builds.append({"dockerfile": dockerfile, "tag": tag, "labels": labels, "data": data})
        self.tags.add(tag)

    def list(self, filters: dict) -> list[FakeImage]:
        return [FakeImage(tag) for tag in sorted(self.tags)]

    def remove(self, image_id: str, force: bool) -> None:
        self.removed.append(image_id)
        self.tags.discard(image_id)


class FakeNetwork:
    def __init__(self, name: str, labels: dict[str, str]) -> None:
        self.id = f"net-{name}"
        self.name = name
        self.labels = labels
        self.removed = False
        self.attrs = {"IPAM": {"Config": [{"Gateway": FakeNetworks.BRIDGE_ADDRESS}]}}

    def reload(self) -> None:
        pass

    def remove(self) -> None:
        self.removed = True


class FakeNetworks:
    BRIDGE_ADDRESS = "172.30.0.1"
    GATEWAY_CONTAINER_ADDRESS = "172.30.0.2"

    def __init__(self) -> None:
        self.created: list[FakeNetwork] = []

    def create(self, name: str, driver: str, labels: dict, check_duplicate: bool) -> FakeNetwork:
        network = FakeNetwork(name, labels)
        self.created.append(network)
        return network

    def get(self, key: str) -> FakeNetwork:
        for network in self.created:
            if key in (network.id, network.name) and not network.removed:
                return network
        raise docker.errors.NotFound(f"No such network: {key}")

    def list(self, names=None, filters=None) -> list[FakeNetwork]:
        live = [n for n in self.created if not n.removed]
        return [n for n in live if names is None or n.name in names]


class FakeDocker:
    def __init__(self, images: set[str] | None = None) -> None:
        self.images = FakeImages(images)
        self.containers = FakeContainers()
        self.networks = FakeNetworks()

    @property
    def box_builds(self) -> list[dict]:
        """Box image builds (the gateway image is built from a custom context)."""
        return [build for build in self.images.builds if build["dockerfile"] is not None]


class RecordingRunner:
    """Stands in for subprocess.run when TerminalExec calls `docker exec`."""

    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode)


class FakeProxy(NetworkProxy):
    """Records its lifecycle instead of listening on a socket."""

    PORT = 3128

    def __init__(self, network: NetworkSpec, project_root: Path) -> None:
        self.network = network
        self.project_root = project_root
        self.started = False
        self.stopped = False

    def start(self, port: int = 0) -> int:
        self.started = True
        return self.PORT

    def stop(self) -> None:
        self.stopped = True


class FakeProxyFactory:
    def __init__(self) -> None:
        self.created: list[FakeProxy] = []

    def __call__(self, network: NetworkSpec, project_root: Path) -> FakeProxy:
        self.created.append(FakeProxy(network, project_root))
        return self.created[-1]
