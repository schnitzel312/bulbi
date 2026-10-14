"""Tests for the shared-box orchestration (spec §4, §8, §9.4) with fake Docker."""

import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import ClassVar

import docker.errors
import pytest

from bulbi.agents import Agent, BoxContext, ContainerHandle
from bulbi.container.gateway import GatewayManager
from bulbi.container.manager import BoxManager
from bulbi.container.sessions import DockerSessionTracker
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError, SpecError
from bulbi.gateway.config import CONFIG_ENV, GatewayConfig, HostAccess
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.image.gateway import GatewayImageBuilder
from bulbi.project import Project, ProjectLocator
from bulbi.sandbox import BoxOrchestrator, SandboxObserver, SandboxServices, SandboxSession
from bulbi.sandbox.lock import FileBoxLock
from bulbi.sandbox.planner import BoxObservation, BoxPlan, BoxPlanner, OutdatedBoxError
from bulbi.spec import BoxSpec, BulbiSpec, MountSpec, NetworkSpec, ToolsSpec
from bulbi.tools import ToolRegistry
from tests.fakes import (
    FakeContainer,
    FakeDocker,
    FakeExecRun,
    FakeNetworks,
    RecordingRunner,
    fake_secret_readers,
)
from tests.repos import add_worktree, make_repo


class RecordingAgent(Agent):
    name = "recorder"
    launch_command = ("recorder",)

    def __init__(self, fail: bool = False) -> None:
        self.prepared: list[BoxContext] = []
        self.refreshed: list[BoxContext] = []
        self._fail = fail

    def prepare_container(self, container: ContainerHandle, context: BoxContext) -> None:
        if self._fail:
            raise SandboxError("prepare failed")
        self.prepared.append(context)

    def refresh(self, container: ContainerHandle, context: BoxContext) -> None:
        self.refreshed.append(context)


class RecordingObserver(SandboxObserver):
    def __init__(self) -> None:
        self.events: list[str] = []

    def building_image(self, spec):
        self.events.append("build")

    def starting_gateway(self):
        self.events.append("gateway")

    def starting_container(self):
        self.events.append("box")

    def running(self, label, command):
        self.events.append(f"{label}: {' '.join(command)}")


class FakeRelayLauncher:
    instances: ClassVar[list["FakeRelayLauncher"]] = []

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.ensured: list[tuple[str, list[int], str]] = []
        self.stopped = 0
        FakeRelayLauncher.instances.append(self)

    def ensure(self, bind_host, ports, allowed_source):
        self.ensured.append((bind_host, list(ports), allowed_source))

    def stop(self):
        self.stopped += 1


@pytest.fixture(autouse=True)
def _reset_relays():
    FakeRelayLauncher.instances = []


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
        gateway_images=GatewayImageBuilder(client),
        boxes=BoxManager(client),
        gateways=GatewayManager(client, clock=lambda: 0.0, sleep=lambda _: None),
        sessions=DockerSessionTracker(client),
        terminal=TerminalExec(runner=runner, is_terminal=lambda: False),
        relay_launcher_factory=FakeRelayLauncher,  # type: ignore[arg-type]
        host_access=HostAccess.DOCKER_DESKTOP,
        log_owner=(501, 20),
        secret_readers=fake_secret_readers({}),
    )


def _spec(allow=("pypi.org",), deny=(), idle="10m", exclude=()) -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo", agent="recorder", idle_timeout=idle),
        tools=ToolsSpec(allow=["git"]),
        mounts=[MountSpec(path=".", exclude=list(exclude))],
        network=NetworkSpec(allow=list(allow), deny=list(deny)),
    )


def _orchestrator(project, services, spec=None, agent=None, profile=None, observer=None):
    return BoxOrchestrator(
        spec or _spec(), project, agent or RecordingAgent(), services, observer, profile
    )


def _containers(client: FakeDocker, role: str | None = None) -> list[FakeContainer]:
    unique = {id(c): c for c in client.containers.by_key.values() if not c.removed}.values()
    if role == "gateway":
        return [c for c in unique if c.labels.get("bulbi.role") == "gateway"]
    if role == "box":
        return [c for c in unique if c.labels.get("bulbi.role") != "gateway"]
    return list(unique)


def _start_session(client: FakeDocker, box: FakeContainer, exec_id: str = "s1") -> None:
    box.attrs["ExecIDs"] = [*box.attrs.get("ExecIDs", []), exec_id]
    client.api.execs[exec_id] = {
        "Running": True,
        "ProcessConfig": {"entrypoint": "/entrypoint.sh"},
    }


def _run_kwargs(client: FakeDocker) -> tuple[dict, dict]:
    (_, gateway), (_, box) = client.containers.run_calls[:2]
    return gateway, box


# ---- Create (spec §4) ------------------------------------------------------------------------


def test_first_session_creates_gateway_then_box(tmp_path, client, services):
    agent, observer = RecordingAgent(), RecordingObserver()
    box = _orchestrator(Project.plain(tmp_path), services, agent=agent, observer=observer).ensure()
    gateway, box_kwargs = _run_kwargs(client)
    assert box_kwargs["network_mode"] == f"container:id-{gateway['name']}"
    assert box.id == f"id-{box_kwargs['name']}"
    assert gateway["name"] == box_kwargs["name"] + "-gw"
    assert client.networks.created[0].name == box_kwargs["name"] + "-net"
    assert observer.events == ["build", "gateway", "box"]
    assert len(agent.prepared) == 1
    assert agent.prepared[0].project_dirs == (str(tmp_path.resolve()),)
    assert agent.prepared[0].environment == {}  # no proxy variables


def test_gateway_is_hardened_and_configured(tmp_path, client, services):
    spec = _spec(allow=["pypi.org", "host:5432"], deny=["evil.test"])
    _orchestrator(Project.plain(tmp_path), services, spec).ensure()
    gateway, box = _run_kwargs(client)
    assert gateway["cap_drop"] == ["ALL"]
    assert gateway["cap_add"] == ["NET_ADMIN", "SETUID", "SETGID"]
    assert gateway["read_only"] is True
    assert gateway["security_opt"] == ["no-new-privileges"]
    assert gateway["labels"]["bulbi.role"] == "gateway"
    assert "ports" not in gateway and "ports" not in box
    assert box["cap_drop"] == ["ALL"] and box["pids_limit"] == 512
    config = GatewayConfig.from_json(gateway["environment"][CONFIG_ENV])
    assert (config.allow, config.deny, config.log_owner) == (
        ["pypi.org", "host:5432"], ["evil.test"], (501, 20),
    )  # fmt: skip
    assert gateway["mounts"][0]["Source"] == str(tmp_path.resolve() / ".bulbi")


def test_malformed_rules_fail_before_anything_starts(tmp_path, client, services):
    with pytest.raises(SpecError, match=r"\[::1"):
        _orchestrator(Project.plain(tmp_path), services, _spec(allow=["[::1"])).ensure()
    assert client.containers.run_calls == [] and client.networks.created == []


# ---- Attach / start / recreate / refuse (spec §8.2) ----------------------------------------


def test_second_session_attaches_and_only_refreshes(tmp_path, client, services):
    agent = RecordingAgent()
    project = Project.plain(tmp_path)
    first = _orchestrator(project, services, agent=agent).ensure()
    second = _orchestrator(project, services, agent=agent).ensure()
    assert first.id == second.id
    assert len(client.containers.run_calls) == 2  # one gateway + one box, ever
    assert len(agent.prepared) == 1 and len(agent.refreshed) == 1


def test_stopped_box_is_started_again_gateway_first(tmp_path, client, services):
    agent = RecordingAgent()
    project = Project.plain(tmp_path)
    orchestrator = _orchestrator(project, services, agent=agent)
    box = orchestrator.ensure()
    assert orchestrator.stop()
    (gateway,) = _containers(client, "gateway")
    box_container = client.containers.get(box.id)
    assert gateway.status == box_container.status == "exited"

    order: list[str] = []
    gateway.start = lambda: (order.append("gateway"), setattr(gateway, "status", "running"))  # type: ignore[method-assign]
    box_container.start = lambda: (
        order.append("box"),
        setattr(box_container, "status", "running"),
    )  # type: ignore[method-assign]
    again = _orchestrator(project, services, agent=agent).ensure()
    assert again.id == box.id
    assert order == ["gateway", "box"]
    assert len(client.containers.run_calls) == 2  # nothing new created
    assert len(agent.prepared) == 2  # prepare runs once per container start


def test_spec_change_without_sessions_recreates_box_and_gateway(tmp_path, client, services):
    project = Project.plain(tmp_path)
    old = _orchestrator(project, services).ensure()
    new = _orchestrator(project, services, _spec(allow=["pypi.org", "example.com"])).ensure()
    assert client.containers.get(new.id).labels["bulbi.spec_hash"] != ""
    assert len(client.containers.run_calls) == 4
    assert len(_containers(client, "box")) == 1 and len(_containers(client, "gateway")) == 1
    assert old.id == new.id  # same name; the old container was removed first
    assert client.networks.created[0].removed and not client.networks.created[1].removed


def test_spec_change_with_sessions_is_refused(tmp_path, client, services):
    project = Project.plain(tmp_path)
    box = _orchestrator(project, services).ensure()
    _start_session(client, client.containers.get(box.id), "s1")
    _start_session(client, client.containers.get(box.id), "s2")
    with pytest.raises(
        OutdatedBoxError, match=r"older spec with 2 active sessions.*bulbi restart"
    ):
        _orchestrator(project, services, _spec(allow=["example.com"])).ensure()
    assert len(client.containers.run_calls) == 2


def test_lock_serialises_concurrent_starts(tmp_path, client, services):
    real_create = client.networks.create

    def slow_create(*args, **kwargs):
        time.sleep(0.2)  # Widen the race window: without the lock both threads create.
        return real_create(*args, **kwargs)

    client.networks.create = slow_create
    project = Project.plain(tmp_path)
    services = replace(services, lock_factory=lambda d: FileBoxLock(d / "box.lock"))
    results: list[str] = []
    threads = [
        threading.Thread(
            target=lambda: results.append(_orchestrator(project, services).ensure().id)
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(results)) == 1
    assert len(_containers(client, "box")) == 1
    assert len(client.networks.created) == 1


def test_profiles_map_to_distinct_boxes(tmp_path, client, services):
    project = Project.plain(tmp_path)
    plain = _orchestrator(project, services).ensure()
    profiled = _orchestrator(project, services, profile="reviewer").ensure()
    assert plain.id != profiled.id
    assert len(_containers(client, "box")) == 2 and len(_containers(client, "gateway")) == 2


# ---- Release and idle shutdown (spec §8.3) ------------------------------------------------


def test_last_session_with_idle_zero_stops_box_and_gateway(tmp_path, client, services):
    project = Project.plain(tmp_path)
    orchestrator = _orchestrator(project, services, _spec(idle="0"))
    box = client.containers.get(orchestrator.ensure().id)
    (gateway,) = _containers(client, "gateway")

    _start_session(client, box, "other")
    orchestrator.release()  # another terminal is still working
    assert box.status == gateway.status == "running"

    client.api.execs["other"]["Running"] = False
    orchestrator.release()
    assert box.status == gateway.status == "exited"
    assert not box.removed and not gateway.removed  # kept for a fast restart


def test_release_with_idle_timeout_leaves_the_box_to_its_watcher(tmp_path, client, services):
    orchestrator = _orchestrator(Project.plain(tmp_path), services, _spec(idle="10m"))
    box = client.containers.get(orchestrator.ensure().id)
    orchestrator.release()
    assert box.status == "running"
    assert client.containers.run_calls[1][1]["command"][-1] == "600"


def test_gateway_of_a_stopped_box_is_reaped_by_the_next_command(tmp_path, client, services):
    project = Project.plain(tmp_path)
    box = client.containers.get(_orchestrator(project, services).ensure().id)
    box.status = "exited"  # the idle watcher stopped it
    (gateway,) = _containers(client, "gateway")
    other = Project.plain(tmp_path / "other")
    (tmp_path / "other").mkdir()
    _orchestrator(other, services).ensure()
    assert gateway.status == "exited"


# ---- Planner (pure) ------------------------------------------------------------------------


def _state(status="running", spec_hash="h"):
    from bulbi.container.manager import ContainerState

    return ContainerState("id", "n", status, {"bulbi.spec_hash": spec_hash})


@pytest.mark.parametrize(
    ("box", "gateway", "sessions", "plan"),
    [
        (None, None, 0, BoxPlan.CREATE),
        ("running", "running", 3, BoxPlan.ATTACH),
        ("exited", "exited", 0, BoxPlan.START),
        ("exited", "running", 0, BoxPlan.START),
        ("running", "exited", 0, BoxPlan.START),
        ("running", None, 0, BoxPlan.RECREATE),
    ],
)
def test_planner(box, gateway, sessions, plan):
    observation = BoxObservation(
        _state(box) if box else None, _state(gateway) if gateway else None, sessions
    )
    assert BoxPlanner().plan(observation, "h") is plan


def test_planner_refuses_restarting_a_gateway_under_live_sessions():
    with pytest.raises(SandboxError, match="gateway stopped while 1 sessions"):
        BoxPlanner().plan(BoxObservation(_state(), _state("exited"), 1), "h")


def test_planner_recreates_or_refuses_outdated_boxes():
    observation = BoxObservation(_state(spec_hash="old"), _state(), 0)
    assert BoxPlanner().plan(observation, "new") is BoxPlan.RECREATE
    with pytest.raises(OutdatedBoxError, match="1 active session;"):
        BoxPlanner().plan(replace(observation, active_sessions=1), "new")


# ---- Teardown on failure while creating (spec §6.1) ---------------------------------------


def _nothing_left(client: FakeDocker) -> None:
    assert _containers(client) == []
    assert all(network.removed for network in client.networks.created)


def _fail_ensure(tmp_path, services, error=SandboxError, agent=None):
    with pytest.raises(error):
        _orchestrator(Project.plain(tmp_path), services, agent=agent).ensure()


def test_build_failure_starts_nothing(tmp_path, client, services):
    def failing_build(**kwargs):
        raise docker.errors.BuildError("boom", build_log=[])

    client.images.build = failing_build
    _fail_ensure(tmp_path, services)
    assert client.containers.run_calls == [] and client.networks.created == []


def test_network_failure_leaves_nothing(tmp_path, client, services):
    client.networks.create = lambda *a, **k: (_ for _ in ()).throw(docker.errors.APIError("pool"))
    _fail_ensure(tmp_path, services)
    _nothing_left(client)


def test_gateway_failure_removes_network(tmp_path, client, services):
    client.containers.run = lambda *a, **k: (_ for _ in ()).throw(docker.errors.APIError("img"))
    _fail_ensure(tmp_path, services)
    _nothing_left(client)


def test_gateway_that_never_becomes_ready_is_torn_down(tmp_path, client, services):
    real_run = client.containers.run

    def never_ready(image, **kwargs):
        container = real_run(image, **kwargs)
        container.exec_responses[("cat", "/run/bulbi/ready")] = FakeExecRun(1, b"")
        container.log_output = b"nft: syntax error"
        return container

    client.containers.run = never_ready
    ticks = iter([0.0, 5.0, 11.0])
    gateways = GatewayManager(client, clock=lambda: next(ticks), sleep=lambda _: None)
    with pytest.raises(SandboxError, match="within 10s:\nnft: syntax error"):
        _orchestrator(Project.plain(tmp_path), replace(services, gateways=gateways)).ensure()
    _nothing_left(client)


def test_gateway_that_exits_during_startup_is_reported(tmp_path, client, services):
    real_run = client.containers.run

    def crashes(image, **kwargs):
        container = real_run(image, **kwargs)
        container.status = "exited"
        container.log_output = b"Traceback: boom"
        return container

    client.containers.run = crashes
    with pytest.raises(SandboxError, match="exited during startup:\nTraceback: boom"):
        _orchestrator(Project.plain(tmp_path), services).ensure()
    _nothing_left(client)


def test_box_failure_removes_gateway_and_network(tmp_path, client, services):
    real_run = client.containers.run

    def box_fails(image, **kwargs):
        if "network_mode" in kwargs:
            raise docker.errors.APIError("box failed")
        return real_run(image, **kwargs)

    client.containers.run = box_fails
    _fail_ensure(tmp_path, services)
    _nothing_left(client)


def test_prepare_failure_removes_everything(tmp_path, client, services):
    _fail_ensure(tmp_path, services, agent=RecordingAgent(fail=True))
    _nothing_left(client)


# ---- Sessions ----------------------------------------------------------------------------


def test_session_runs_in_the_invocation_directory_with_the_session_marker(
    tmp_path, runner, services
):
    project = replace(Project.plain(tmp_path), cwd=tmp_path / "src")
    orchestrator = _orchestrator(project, services)
    with SandboxSession(orchestrator, services) as session:
        assert session.run(["make", "test"], "Running") == 7
    (call,) = runner.calls
    assert call[call.index("-w") + 1] == str(tmp_path / "src")
    assert "BULBI_EXEC=session" in call
    assert call[-3:] == ["/entrypoint.sh", "make", "test"]


def test_interrupted_session_still_releases(tmp_path, client, services):
    def interrupted(argv):
        raise KeyboardInterrupt

    services = replace(
        services, terminal=TerminalExec(runner=interrupted, is_terminal=lambda: False)
    )
    orchestrator = _orchestrator(Project.plain(tmp_path), services, _spec(idle="0"))
    with pytest.raises(KeyboardInterrupt), SandboxSession(orchestrator, services) as session:
        session.run(["sleep", "100"], "Running")
    assert all(c.status == "exited" for c in _containers(client))


def test_run_requires_started_session(tmp_path, services):
    session = SandboxSession(_orchestrator(Project.plain(tmp_path), services), services)
    with pytest.raises(SandboxError, match="not started"):
        session.run(["true"], "Running")


# ---- Linux host relay ----------------------------------------------------------------------


def test_linux_host_rules_launch_a_relay_bound_to_the_bridge(tmp_path, client, services):
    services = replace(services, host_access=HostAccess.BRIDGE_RELAY)
    orchestrator = _orchestrator(
        Project.plain(tmp_path), services, _spec(allow=["host:5432,6000-6001"])
    )
    orchestrator.ensure()
    (launcher,) = FakeRelayLauncher.instances
    assert launcher.ensured == [
        (FakeNetworks.BRIDGE_ADDRESS, [5432, 6000, 6001], FakeNetworks.GATEWAY_CONTAINER_ADDRESS)
    ]
    gateway, _ = _run_kwargs(client)
    assert (
        GatewayConfig.from_json(gateway["environment"][CONFIG_ENV]).host_address
        == FakeNetworks.BRIDGE_ADDRESS
    )
    orchestrator.stop()
    assert sum(launcher.stopped for launcher in FakeRelayLauncher.instances) >= 1


def test_no_relay_without_host_rules_or_on_docker_desktop(tmp_path, services):
    _orchestrator(
        Project.plain(tmp_path), replace(services, host_access=HostAccess.BRIDGE_RELAY)
    ).ensure()
    _orchestrator(
        Project.plain(tmp_path), services, _spec(allow=["host:5432"]), profile="x"
    ).ensure()
    assert all(not launcher.ensured for launcher in FakeRelayLauncher.instances)


# ---- Git worktrees (spec §9) ----------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "code" / "app")


def test_every_worktree_attaches_to_the_same_box(tmp_path, client, services, repo):
    trees = tmp_path / "trees"
    a = add_worktree(repo, trees / "a", "a")
    b = add_worktree(repo, trees / "b", "b")
    ids = {
        _orchestrator(ProjectLocator().locate(path), services).ensure().id for path in (repo, a, b)
    }
    assert len(ids) == 1
    assert len(_containers(client, "box")) == 1


def test_trust_covers_main_checkout_container_dir_and_worktrees(tmp_path, services, repo):
    trees = tmp_path / "trees"
    a = add_worktree(repo, trees / "a", "a")
    agent = RecordingAgent()
    _orchestrator(ProjectLocator().locate(a), services, agent=agent).ensure()
    assert agent.prepared[0].project_dirs == (str(repo), str(trees.resolve()), str(a))


def test_late_worktree_in_mounted_dir_is_allowed(tmp_path, services, repo):
    trees = tmp_path / "trees"
    add_worktree(repo, trees / "a", "a")
    _orchestrator(ProjectLocator().locate(repo), services).ensure()
    late = add_worktree(repo, trees / "late", "late")
    # Same spec as the running box, so it attaches; no excluded files: allowed.
    box = _orchestrator(ProjectLocator().locate(late), services).ensure()
    assert box.id == _orchestrator(ProjectLocator().locate(repo), services).ensure().id


def test_late_worktree_with_excluded_files_is_refused(tmp_path, services, repo):
    trees = tmp_path / "trees"
    add_worktree(repo, trees / "a", "a")
    spec = _spec(exclude=[".env"])
    _orchestrator(ProjectLocator().locate(repo), services, spec).ensure()
    late = add_worktree(repo, trees / "late", "late")
    (late / ".env").write_text("SECRET=1")
    with pytest.raises(SandboxError, match="excluded files that the running box can't hide"):
        _orchestrator(ProjectLocator().locate(late), services, spec).ensure()


def test_late_scattered_worktree_is_not_mounted_and_says_so(tmp_path, client, services, repo):
    _orchestrator(ProjectLocator().locate(repo), services).ensure()
    box = _containers(client, "box")[0]
    box.attrs["Mounts"] = [{"Destination": str(repo)}]
    late = add_worktree(repo, tmp_path / "elsewhere" / "late", "late")
    (tmp_path / "elsewhere" / "unrelated").mkdir()
    # The scattered worktree changes the mounted checkouts, so with live sessions the spec
    # is outdated; without sessions the box is recreated to include it.
    _start_session(client, box)
    with pytest.raises(OutdatedBoxError):
        _orchestrator(ProjectLocator().locate(late), services).ensure()


# ---- secrets (spec §10.3) ---------------------------------------------------------------------


def _secret_spec(**secrets) -> BulbiSpec:
    return replace(_spec(), secrets=secrets)


def test_missing_user_secret_stops_the_run_before_anything_starts(tmp_path, client, services):
    from bulbi.secrets import SecretError
    from bulbi.spec import SecretSpec

    spec = _secret_spec(GITHUB_TOKEN=SecretSpec(from_source="env"))
    with pytest.raises(SecretError, match="GITHUB_TOKEN"):
        _orchestrator(Project.plain(tmp_path), services, spec).ensure()
    assert client.images.builds == [] and client.containers.run_calls == []


def test_file_secrets_are_rewritten_on_every_attach(tmp_path, client, services):
    from bulbi.spec import SecretSpec

    values = {"~/.npmrc": "v1"}
    services = replace(services, secret_readers=fake_secret_readers(values))
    spec = _secret_spec(
        NPM_RC=SecretSpec(from_source="file", source="~/.npmrc", to="file", path="~/.npmrc")
    )
    project = Project.plain(tmp_path)
    box = client.containers.get(_orchestrator(project, services, spec).ensure().id)
    values["~/.npmrc"] = "v2"  # rotated on the host
    _orchestrator(project, services, spec).ensure()
    written = [archive for path, archive in box.archives if path == "/home/bulbi"]
    assert len(written) == 2
    assert b"v2" in written[-1] and b"v1" in written[0]


def test_env_secrets_reach_the_session_without_appearing_in_arguments(tmp_path, runner, services):
    from bulbi.spec import SecretSpec

    services = replace(services, secret_readers=fake_secret_readers({"GITHUB_TOKEN": "tok-123"}))
    spec = _secret_spec(GITHUB_TOKEN=SecretSpec(from_source="env"))
    orchestrator = _orchestrator(Project.plain(tmp_path), services, spec)
    with SandboxSession(orchestrator, services) as session:
        session.run(["env"], "Running")
    (argv,) = runner.calls
    assert "GITHUB_TOKEN" in argv and not any("tok-123" in arg for arg in argv)
    assert runner.envs[0]["GITHUB_TOKEN"] == "tok-123"
    box_kwargs = [
        kw for _, kw in services.boxes._docker.containers.run_calls if "network_mode" in kw
    ]
    assert "GITHUB_TOKEN" not in box_kwargs[0]["environment"]  # never baked into the container


def test_gateway_can_redirect_dns_sent_to_any_resolver(tmp_path, client, services):
    """Redirecting eth0-bound DNS to the loopback resolver needs route_localnet."""
    _orchestrator(Project.plain(tmp_path), services).ensure()
    gateway, _ = _run_kwargs(client)
    assert gateway["sysctls"] == {"net.ipv4.conf.all.route_localnet": "1"}
