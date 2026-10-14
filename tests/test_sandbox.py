"""Tests for the sandbox session orchestration (fake Docker, fake relay)."""

from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import docker.errors
import pytest

from bulbi.agents import Agent, ContainerHandle
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.gateway import GatewayManager
from bulbi.container.manager import BoxManager
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError, SpecError
from bulbi.gateway.config import CONFIG_ENV, GatewayConfig, HostAccess
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.image.gateway import GatewayImageBuilder
from bulbi.sandbox import SandboxObserver, SandboxServices, SandboxSession
from bulbi.spec import BoxSpec, BulbiSpec, MountSpec, NetworkSpec, ToolsSpec
from bulbi.tools import ToolRegistry
from tests.fakes import FakeDocker, FakeExecRun, FakeNetworks, RecordingRunner


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

    def starting_gateway(self):
        self.events.append("gateway")

    def starting_container(self):
        self.events.append("box")

    def running(self, label, command):
        self.events.append(f"{label}: {' '.join(command)}")


class FakeRelay:
    def __init__(self, bind_host: str, ports) -> None:
        self.bind_host = bind_host
        self.ports = list(ports)
        self.started = False
        self.stopped = False
        self.allowed_source: str | None = None

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def allow_source(self, address: str) -> None:
        self.allowed_source = address


@pytest.fixture
def client() -> FakeDocker:
    return FakeDocker()


@pytest.fixture
def runner() -> RecordingRunner:
    return RecordingRunner(returncode=7)


@pytest.fixture
def relays() -> list[FakeRelay]:
    return []


@pytest.fixture
def services(client: FakeDocker, runner: RecordingRunner, relays) -> SandboxServices:
    def relay_factory(bind_host, ports):
        relays.append(FakeRelay(bind_host, ports))
        return relays[-1]

    return SandboxServices(
        images=ImageBuilder(client, DockerfileBuilder(ToolRegistry.builtin())),
        gateway_images=GatewayImageBuilder(client),
        boxes=BoxManager(client),
        gateways=GatewayManager(client, clock=lambda: 0.0, sleep=lambda _: None),
        terminal=TerminalExec(runner=runner, is_terminal=lambda: False),
        environment=EnvironmentBuilder(host_env={}),
        relay_factory=relay_factory,  # type: ignore[arg-type]
        host_access=HostAccess.DOCKER_DESKTOP,
        log_owner=(501, 20),
    )


def _spec(allow=("pypi.org",), deny=()) -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo", agent="recorder"),
        tools=ToolsSpec(allow=["git"]),
        mounts=[MountSpec(path=".")],
        network=NetworkSpec(allow=list(allow), deny=list(deny)),
    )


def _live(client: FakeDocker) -> list:
    return [
        c for c in {id(c): c for c in client.containers.by_key.values()}.values() if not c.removed
    ]


def _run_kwargs(client: FakeDocker) -> tuple[dict, dict]:
    (_, gateway), (_, box) = client.containers.run_calls
    return gateway, box


def test_session_starts_gateway_then_box_and_cleans_up(tmp_path, client, runner, services):
    agent = RecordingAgent()
    observer = RecordingObserver()

    with SandboxSession(_spec(), tmp_path, agent, services, observer) as session:
        assert session.run(["make", "test"], "Running") == 7
        assert len(_live(client)) == 2

    gateway, box = _run_kwargs(client)
    assert box["network_mode"] == f"container:id-{gateway['name']}"
    assert observer.events == ["build demo", "gateway", "box", "Running: make test"]
    assert runner.calls[0][-2:] == ["make", "test"]
    assert _live(client) == []
    assert all(network.removed for network in client.networks.created)
    assert agent.prepared_with == [{}]  # no proxy variables: tools need no configuration


def test_box_is_hardened(tmp_path, client, services):
    with SandboxSession(_spec(), tmp_path, RecordingAgent(), services):
        _, box = _run_kwargs(client)
    assert box["cap_drop"] == ["ALL"]
    assert box["security_opt"] == ["no-new-privileges"]
    assert box["pids_limit"] == 512
    assert "ports" not in box
    assert "extra_hosts" not in box
    assert "privileged" not in box


def test_gateway_is_hardened_and_configured(tmp_path, client, services):
    with SandboxSession(_spec(allow=["pypi.org", "host:5432"], deny=["evil.test"]), tmp_path,
                        RecordingAgent(), services):  # fmt: skip
        gateway, _ = _run_kwargs(client)
    assert gateway["cap_drop"] == ["ALL"]
    assert gateway["cap_add"] == ["NET_ADMIN", "SETUID", "SETGID"]
    assert gateway["read_only"] is True
    assert gateway["security_opt"] == ["no-new-privileges"]
    assert gateway["labels"]["bulbi.role"] == "gateway"
    assert gateway["network"] == client.networks.created[0].name
    assert "ports" not in gateway
    config = GatewayConfig.from_json(gateway["environment"][CONFIG_ENV])
    assert (config.default, config.allow, config.deny) == (
        "deny", ["pypi.org", "host:5432"], ["evil.test"],
    )  # fmt: skip
    assert config.log_owner == (501, 20)
    assert gateway["mounts"][0]["Source"] == str(tmp_path / ".bulbi")


def test_malformed_rules_fail_before_anything_starts(tmp_path, client, services):
    with pytest.raises(SpecError, match=r"\[::1"):
        SandboxSession(_spec(allow=["[::1"]), tmp_path, RecordingAgent(), services).__enter__()
    assert client.containers.run_calls == []
    assert client.networks.created == []


def test_run_requires_started_session(tmp_path, services):
    session = SandboxSession(_spec(), tmp_path, RecordingAgent(), services)
    with pytest.raises(SandboxError, match="not started"):
        session.run(["true"], "Running")


# ---- teardown completeness on failure at every step (spec §6.1) -----------------------


def _assert_nothing_left(client: FakeDocker) -> None:
    assert _live(client) == []
    assert all(network.removed for network in client.networks.created)


def test_build_failure_starts_nothing(tmp_path, client, services):
    def failing_build(**kwargs):
        raise docker.errors.BuildError("boom", build_log=[])

    client.images.build = failing_build
    with pytest.raises(SandboxError, match="failed to build image"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services).__enter__()
    assert client.containers.run_calls == []
    assert client.networks.created == []


def test_network_failure_leaves_nothing(tmp_path, client, services):
    def failing_create(*args, **kwargs):
        raise docker.errors.APIError("pool overlaps")

    client.networks.create = failing_create
    with pytest.raises(SandboxError, match="pool overlaps"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services).__enter__()
    _assert_nothing_left(client)


def test_gateway_start_failure_removes_network(tmp_path, client, services):
    def failing_run(image, **kwargs):
        raise docker.errors.APIError("no such image")

    client.containers.run = failing_run
    with pytest.raises(SandboxError, match="no such image"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services).__enter__()
    _assert_nothing_left(client)


def test_gateway_that_never_becomes_ready_is_torn_down(tmp_path, client, services):
    real_run = client.containers.run

    def gateway_never_ready(image, **kwargs):
        container = real_run(image, **kwargs)
        container.exec_responses[("cat", "/run/bulbi/ready")] = FakeExecRun(1, b"")
        container.log_output = b"nft: syntax error"
        return container

    client.containers.run = gateway_never_ready
    ticks = iter([0.0, 5.0, 11.0])
    gateways = GatewayManager(client, clock=lambda: next(ticks), sleep=lambda _: None)
    with pytest.raises(SandboxError, match="did not become ready within 10s:\nnft: syntax error"):
        SandboxSession(
            _spec(), tmp_path, RecordingAgent(), replace(services, gateways=gateways)
        ).__enter__()
    _assert_nothing_left(client)


def test_gateway_that_exits_during_startup_is_reported(tmp_path, client, services):
    real_run = client.containers.run

    def gateway_crashes(image, **kwargs):
        container = real_run(image, **kwargs)
        container.status = "exited"
        container.log_output = b"Traceback: boom"
        return container

    client.containers.run = gateway_crashes
    with pytest.raises(SandboxError, match="exited during startup:\nTraceback: boom"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services).__enter__()
    _assert_nothing_left(client)


def test_box_start_failure_stops_gateway_and_network(tmp_path, client, services):
    real_run = client.containers.run

    def box_fails(image, **kwargs):
        if "network_mode" in kwargs:
            raise docker.errors.APIError("port conflict")
        return real_run(image, **kwargs)

    client.containers.run = box_fails
    with pytest.raises(SandboxError, match="port conflict"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services).__enter__()
    _assert_nothing_left(client)


def test_prepare_failure_tears_everything_down(tmp_path, client, services):
    with pytest.raises(SandboxError, match="prepare failed"):
        SandboxSession(_spec(), tmp_path, RecordingAgent(fail=True), services).__enter__()
    _assert_nothing_left(client)


def test_interrupted_command_still_cleans_up(tmp_path, client, services):
    def interrupted(argv):
        raise KeyboardInterrupt

    services = replace(
        services, terminal=TerminalExec(runner=interrupted, is_terminal=lambda: False)
    )
    with (
        pytest.raises(KeyboardInterrupt),
        SandboxSession(_spec(), tmp_path, RecordingAgent(), services) as session,
    ):
        session.run(["sleep", "100"], "Running")
    _assert_nothing_left(client)


# ---- host relay (Linux) ---------------------------------------------------------------


def test_linux_host_rules_start_a_relay_for_the_gateway(tmp_path, client, services, relays):
    services = replace(services, host_access=HostAccess.BRIDGE_RELAY)
    spec = _spec(allow=["pypi.org", "host:5432,6000-6001"])
    with SandboxSession(spec, tmp_path, RecordingAgent(), services):
        (relay,) = relays
        assert (relay.bind_host, relay.ports) == (FakeNetworks.BRIDGE_ADDRESS, [5432, 6000, 6001])
        assert relay.started
        assert relay.allowed_source == FakeNetworks.GATEWAY_CONTAINER_ADDRESS
        gateway, _ = _run_kwargs(client)
        config = GatewayConfig.from_json(gateway["environment"][CONFIG_ENV])
        assert config.host_address == FakeNetworks.BRIDGE_ADDRESS
    assert relay.stopped


def test_no_relay_without_host_rules_or_on_docker_desktop(tmp_path, services, relays):
    with SandboxSession(
        _spec(), tmp_path, RecordingAgent(), replace(services, host_access=HostAccess.BRIDGE_RELAY)
    ):
        pass
    with SandboxSession(_spec(allow=["host:5432"]), tmp_path, RecordingAgent(), services):
        pass
    assert relays == []


def test_relay_is_stopped_when_gateway_fails(tmp_path, client, services, relays):
    def failing_run(image, **kwargs):
        raise docker.errors.APIError("boom")

    client.containers.run = failing_run
    services = replace(services, host_access=HostAccess.BRIDGE_RELAY)
    with pytest.raises(SandboxError):
        SandboxSession(
            _spec(allow=["host:5432"]), tmp_path, RecordingAgent(), services
        ).__enter__()
    assert relays[0].stopped


def test_paths(tmp_path: Path):
    assert GatewayManager.gateway_name(_spec(), tmp_path).startswith("bulbi-gw-demo-")
