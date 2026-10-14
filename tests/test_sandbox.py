"""Tests for the sandbox session orchestration (fake Docker, real local proxy)."""

from collections.abc import Mapping

import pytest

from bulbi.agents import Agent
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.execution import ContainerExecutor
from bulbi.container.manager import BoxManager
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.sandbox import SandboxObserver, SandboxServices, SandboxSession
from bulbi.spec import BoxSpec, BulbiSpec, MountSpec, ToolsSpec
from bulbi.tools import ToolRegistry
from tests.fakes import FakeDocker, RecordingRunner


class RecordingAgent(Agent):
    name = "recorder"
    launch_command = ("recorder",)

    def __init__(self, fail: bool = False) -> None:
        self.prepared_with: list[Mapping[str, str]] = []
        self._fail = fail

    def prepare_container(self, container: ContainerExecutor, environment) -> None:
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
