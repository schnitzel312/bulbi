"""Real-Docker test fixtures (``pytest -m docker``; skipped when Docker is unavailable).

Every box created here is named ``<SUITE_PREFIX><run id>...`` and the session fixture
removes exactly the containers, networks, clone volumes and images this run created;
nothing else on the machine is touched. Test projects are temporary git repositories.
"""

from __future__ import annotations

import socket
import textwrap
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import docker
import docker.errors
import pytest

from bulbi.tools import BUILTIN_TOOLS, ToolDefinition, ToolRegistry

SUITE_PREFIX = "bulbitest"
RUN_ID = uuid.uuid4().hex[:6]
TEST_LABEL = "bulbi.test"

# Diagnostics the escape suite needs inside the box (test-only tools).
ESCAPE_TOOLS = ToolRegistry(
    [
        *BUILTIN_TOOLS,
        ToolDefinition("dig", ("dnsutils",), "dig -v"),
        ToolDefinition("nc", ("netcat-openbsd",), "nc -h"),
        ToolDefinition("ssh", ("openssh-client",), "ssh -V"),
        ToolDefinition("nft", ("nftables",), "nft --version"),
        ToolDefinition("ip", ("iproute2",), "ip -V"),
    ]
)


def box_name(suffix: str) -> str:
    return f"{SUITE_PREFIX}{RUN_ID}{suffix}"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/docker/" in str(item.fspath):
            item.add_marker(pytest.mark.docker)


@pytest.fixture(scope="session")
def docker_client() -> Iterator[docker.DockerClient]:
    try:
        client = docker.from_env()
        client.ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not available: {exc}")
    gateway_images_before = {
        tag for image in client.images.list("bulbi/gateway") for tag in image.tags
    }
    yield client
    _cleanup(client, gateway_images_before)


def _cleanup(client: docker.DockerClient, gateway_images_before: set[str]) -> None:
    prefix = f"bulbi-{SUITE_PREFIX}{RUN_ID}"
    containers = client.containers.list(all=True, filters={"label": "bulbi=true"})
    containers += client.containers.list(all=True, filters={"label": f"{TEST_LABEL}={RUN_ID}"})
    ours = [
        c for c in containers if c.name.startswith(prefix) or c.labels.get(TEST_LABEL) == RUN_ID
    ]
    ours.sort(key=lambda c: c.name.endswith("-gw"))  # boxes before gateways
    for container in ours:
        container.remove(force=True)
    for network in client.networks.list(filters={"label": "bulbi=true"}):
        if network.name.startswith(prefix):
            network.remove()
    for volume in client.volumes.list(filters={"label": "bulbi=true"}):
        if volume.name.startswith(f"bulbi-git-{SUITE_PREFIX}{RUN_ID}"):
            volume.remove(force=True)
    for image in client.images.list(filters={"label": "bulbi=true"}):
        tags = set(image.tags)
        built_box = any(tag.startswith(f"bulbi/{SUITE_PREFIX}{RUN_ID}") for tag in tags)
        built_gateway = any(t.startswith("bulbi/gateway:") for t in tags) and not (
            tags & gateway_images_before
        )
        if built_box or built_gateway:
            client.images.remove(image.id, force=True)


def write_spec(  # noqa: PLR0913 - every argument is a spec knob
    root: Path,
    name: str,
    *,
    allow: list[str],
    deny: list[str] = (),  # type: ignore[assignment]
    default: str = "deny",
    tools: list[str] = ("git",),  # type: ignore[assignment]
    idle: str = "10m",
    extra: str = "",
) -> None:
    def toml_list(items: list[str]) -> str:
        return "[" + ", ".join(f'"{item}"' for item in items) + "]"

    (root / "bulbi.toml").write_text(
        textwrap.dedent(
            f"""\
            spec = "0.1"
            [box]
            name = "{name}"
            agent = "true"
            idle_timeout = "{idle}"
            [tools]
            allow = {toml_list(list(tools))}
            [[mount]]
            path = "."
            exclude = [".env"]
            [network]
            default = "{default}"
            allow = {toml_list(allow)}
            deny = {toml_list(list(deny))}
            """
        )
        + extra
    )


@pytest.fixture(scope="session")
def echo_server() -> Iterator[int]:
    """A TCP echo server on the host's 127.0.0.1."""
    server = socket.create_server(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                connection, _ = server.accept()
            except OSError:
                return
            with connection:
                data = connection.recv(1024)
                connection.sendall(data)

    threading.Thread(target=serve, daemon=True).start()
    yield port
    server.close()


def free_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as spare:
        return int(spare.getsockname()[1])
