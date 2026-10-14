"""Tests for the sandbox session orchestration.

Docker is always faked. Most tests also use a fake proxy; a few start the real proxy
on localhost to check that its port is bound and released.
"""

from collections.abc import Mapping
from dataclasses import replace

import docker.errors
import pytest

from bulbi.agents import Agent, ContainerHandle
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.manager import BoxManager
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.sandbox import SandboxObserver, SandboxServices, SandboxSession
from bulbi.spec import BoxSpec, BulbiSpec, MountSpec, ToolsSpec
from bulbi.tools import ToolRegistry
from tests.fakes import FakeDocker, FakeProxy, FakeProxyFactory, RecordingRunner


class RecordingAgent(Agent):
    name = "recorder"
    launch_command = ("recorder",)

    def __init__(self, fail: bool = False) -> None:
        self.prepared_with: list[Mapping[str, str]] = []
        self._fail = fail

    def prepare_container(self, container: ContainerHandle, environment) -> None:
        if self._fail:
            raise SandboxError("prepare failed")
        self.prepared_with.append(dict(environment))


class RecordingObserver(SandboxObserver):
    def __init__(self) -> None:
        self.events: list[str] = []

    def building_image(self, spec):
        self.events.append(f"build {spec.box.name}")

    def starting_container(self):
        self.events.append("start")

    def running(self, label, command):
        self.events.append(f"{label}: {' '.join(command)}")


@pytest.fixture
def client() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def runner() -> RecordingRunner:
    return RecordingRunner(returncode=7)


@pytest.fixture
def services(client: FakeDocker, runner: RecordingRunner) -> SandboxServices:
    return SandboxServices(
        images=ImageBuilder(client, DockerfileBuilder(ToolRegistry.builtin())),
        boxes=BoxManager(client),
        terminal=TerminalExec(runner=runner, is_terminal=lambda: False),
        environment=EnvironmentBuilder(host_env={}, system="Darwin"),
    )


def _spec() -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo", agent="recorder"),
        tools=ToolsSpec(allow=["git"]),
        mounts=[MountSpec(path=".")],
    )


def test_session_runs_command_and_cleans_up(tmp_path, client, runner, services):
    agent = RecordingAgent()
    observer = RecordingObserver()

    with SandboxSession(_spec(), tmp_path, agent, services, observer) as session:
        assert session.run(["make", "test"], "Running") == 7
        (container,) = client.containers.list(all=True, filters={})

    assert len(client.images.builds) == 1  # bug (c): the image is built exactly once
    assert observer.events == ["build demo", "start", "Running: make test"]
    assert runner.calls == [["docker", "exec", container.id, "/entrypoint.sh", "make", "test"]]
    assert container.stopped and container.removed
    proxy_url = agent.prepared_with[0]["HTTP_PROXY"]
    assert proxy_url.startswith("http://host.docker.internal:")


def test_proxy_port_is_released_after_session(tmp_path, services):
    import socket

    agent = RecordingAgent()
    with SandboxSession(_spec(), tmp_path, agent, services):
        port = int(agent.prepared_with[0]["HTTP_PROXY"].rsplit(":", 1)[1])
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=2):
        pass


def test_failed_agent_preparation_still_removes_container(tmp_path, client, services):
    session = SandboxSession(_spec(), tmp_path, RecordingAgent(fail=True), services)
    with pytest.raises(SandboxError, match="prepare failed"):
        session.__enter__()
    (container,) = {id(c): c for c in client.containers.by_key.values()}.values()
    assert container.stopped and container.removed


def test_run_requires_started_session(tmp_path, services):
    session = SandboxSession(_spec(), tmp_path, RecordingAgent(), services)
    with pytest.raises(SandboxError, match="not started"):
        session.run(["true"], "Running")


def test_mounts_are_planned_for_the_project(tmp_path, client, services):
    with SandboxSession(_spec(), tmp_path, RecordingAgent(), services):
        ((_, kwargs),) = client.containers.run_calls
    assert kwargs["mounts"][0]["Source"] == str(tmp_path.resolve())


# ---- Cleanup on the failure paths (M2) ------------------------------------------


@pytest.fixture
def proxies() -> FakeProxyFactory:
    return FakeProxyFactory()


@pytest.fixture
def fake_proxy_services(services: SandboxServices, proxies: FakeProxyFactory) -> SandboxServices:
    return replace(services, proxy_factory=proxies)


def _live_containers(client: FakeDocker) -> list:
    return [c for c in client.containers.by_key.values() if not c.removed]


def test_build_failure_starts_nothing(tmp_path, client, proxies, fake_proxy_services):
    def failing_build(**kwargs):
        raise docker.errors.BuildError("boom", build_log=[])

    client.images.build = failing_build
    with pytest.raises(SandboxError, match="failed to build image"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), fake_proxy_services).__enter__()
    assert proxies.created == []
    assert client.containers.run_calls == []


def test_container_start_failure_stops_proxy(tmp_path, client, proxies, fake_proxy_services):
    def failing_run(image, **kwargs):
        raise docker.errors.APIError("port conflict")

    client.containers.run = failing_run
    with pytest.raises(SandboxError, match="port conflict"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), fake_proxy_services).__enter__()
    (proxy,) = proxies.created
    assert proxy.started and proxy.stopped


def test_prepare_failure_stops_container_and_proxy(tmp_path, client, proxies, fake_proxy_services):
    session = SandboxSession(_spec(), tmp_path, RecordingAgent(fail=True), fake_proxy_services)
    with pytest.raises(SandboxError, match="prepare failed"):
        session.__enter__()
    assert _live_containers(client) == []
    assert proxies.created[0].stopped


def test_interrupted_command_still_cleans_up(
    tmp_path, client, runner, proxies, fake_proxy_services
):
    def interrupted(argv):
        raise KeyboardInterrupt

    services = replace(
        fake_proxy_services, terminal=TerminalExec(runner=interrupted, is_terminal=lambda: False)
    )
    with (
        pytest.raises(KeyboardInterrupt),
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services) as session,
    ):
        session.run(["sleep", "100"], "Running")
    assert _live_containers(client) == []
    assert proxies.created[0].stopped


def test_proxy_receives_spec_network_and_project(tmp_path, proxies, fake_proxy_services):
    agent = RecordingAgent()
    with SandboxSession(_spec(), tmp_path, agent, fake_proxy_services):
        pass
    (proxy,) = proxies.created
    assert (proxy.network, proxy.project_root) == (_spec().network, tmp_path)
    assert agent.prepared_with[0]["HTTP_PROXY"].endswith(f":{FakeProxy.PORT}")
