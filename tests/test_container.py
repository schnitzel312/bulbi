"""Tests for mount planning, container environment, terminal exec, and BoxManager."""

from pathlib import Path

import pytest

from bulbi.agents import ClaudeAgent, NoCredentialProvider, UnmanagedAgent
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.manager import BoxInfo, BoxManager
from bulbi.container.mounts import BindMount, MountPlanner
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.spec import BoxSpec, BulbiSpec, LimitsSpec, MountSpec, ToolsSpec
from tests.fakes import FakeContainer, FakeDocker, RecordingRunner

WORKSPACE = "/home/bulbi/workspace"


def _spec(mounts=(), limits=None) -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo"),
        tools=ToolsSpec(),
        mounts=list(mounts),
        limits=limits or LimitsSpec(),
    )


# ---- MountPlanner -----------------------------------------------------------


def test_project_mount_maps_to_workspace(tmp_path: Path):
    plan = MountPlanner(tmp_path).plan(_spec([MountSpec(path=".")]))
    assert plan == [BindMount(str(tmp_path.resolve()), WORKSPACE, read_only=False)]


def test_other_mounts_use_their_directory_name(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    plan = MountPlanner(tmp_path).plan(_spec([MountSpec(path=str(docs), mode="read-only")]))
    assert plan == [BindMount(str(docs), f"{WORKSPACE}/docs", read_only=True)]


def test_existing_excluded_files_are_masked(tmp_path: Path):
    (tmp_path / ".env").write_text("SECRET=1")
    (tmp_path / "a.pem").write_text("")
    spec = _spec([MountSpec(path=".", exclude=[".env", "*.pem", "*.key"])])
    masks = [m for m in MountPlanner(tmp_path).plan(spec) if m.source == "/dev/null"]
    assert masks == [
        BindMount("/dev/null", f"{WORKSPACE}/.env", read_only=True),
        BindMount("/dev/null", f"{WORKSPACE}/a.pem", read_only=True),
    ]


def test_spec_file_is_mounted_read_only(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text("")
    plan = MountPlanner(tmp_path).plan(_spec())
    assert plan == [BindMount(str(tmp_path / "bulbi.toml"), f"{WORKSPACE}/bulbi.toml", True)]


def test_git_worktree_mounts_main_repository(tmp_path: Path):
    main_git = tmp_path / "repo" / ".git"
    (main_git / "worktrees" / "wt").mkdir(parents=True)
    project = tmp_path / "wt"
    project.mkdir()
    (project / ".git").write_text(f"gitdir: {main_git}/worktrees/wt\n")
    plan = MountPlanner(project).plan(_spec())
    assert plan == [BindMount(str(main_git.resolve()), f"{WORKSPACE}/.git-main", False)]


def test_regular_git_checkout_needs_no_extra_mount(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    assert MountPlanner(tmp_path).plan(_spec()) == []


# ---- EnvironmentBuilder -----------------------------------------------------


@pytest.mark.parametrize(
    ("system", "host"), [("Darwin", "host.docker.internal"), ("Linux", "172.17.0.1")]
)
def test_proxy_variables_point_at_host(system: str, host: str):
    env = EnvironmentBuilder(host_env={}, system=system).build(UnmanagedAgent("x"), 4321)
    url = f"http://{host}:4321"
    assert env == {"HTTP_PROXY": url, "HTTPS_PROXY": url, "http_proxy": url, "https_proxy": url}


def test_agent_environment_and_api_keys_are_added():
    agent = ClaudeAgent(credentials=NoCredentialProvider())
    env = EnvironmentBuilder(
        host_env={"ANTHROPIC_API_KEY": "sk-1", "OPENAI_API_KEY": "nope"}, system="Darwin"
    ).build(agent, 1)
    assert env["ANTHROPIC_API_KEY"] == "sk-1"
    assert env["CLAUDE_CODE_NO_FLICKER"] == "1"
    assert "OPENAI_API_KEY" not in env


# ---- TerminalExec -----------------------------------------------------------


@pytest.mark.parametrize(("is_tty", "flags"), [(True, ["-it"]), (False, [])])
def test_terminal_exec_runs_through_entrypoint(is_tty: bool, flags: list[str]):
    runner = RecordingRunner(returncode=3)
    code = TerminalExec(runner=runner, is_terminal=lambda: is_tty).run("cid", ["ls", "-la"])
    assert code == 3
    assert runner.calls == [["docker", "exec", *flags, "cid", "/entrypoint.sh", "ls", "-la"]]


# ---- BoxManager -------------------------------------------------------------


def test_container_name_is_stable_per_project():
    name = BoxManager.container_name(_spec(), Path("/projects/a"))
    assert name == BoxManager.container_name(_spec(), Path("/projects/a"))
    assert name != BoxManager.container_name(_spec(), Path("/projects/b"))
    assert name.startswith("bulbi-demo-")
    assert len(name) == len("bulbi-demo-") + 8


def test_start_runs_idle_labelled_container_with_limits():
    client = FakeDocker()
    mounts = [BindMount("/src", WORKSPACE, read_only=False)]
    spec = _spec(limits=LimitsSpec(cpu=3, memory="512MB"))

    box = BoxManager(client).start(spec, Path("/p"), "img:1", mounts, {"A": "1"})

    ((image, kwargs),) = client.containers.run_calls
    assert image == "img:1"
    assert box.id == f"id-{kwargs['name']}"
    assert kwargs["command"] == ["sleep", "infinity"]
    assert kwargs["labels"] == {"bulbi": "true", "bulbi.box": "demo"}
    assert kwargs["nano_cpus"] == 3 * 10**9
    assert kwargs["mem_limit"] == 512 * 1024**2
    assert kwargs["environment"] == {"A": "1"}
    assert kwargs["mounts"][0]["Target"] == WORKSPACE
    assert kwargs["mounts"][0]["ReadOnly"] is False


def test_start_replaces_stale_container():
    client = FakeDocker()
    name = BoxManager.container_name(_spec(), Path("/p"))
    stale = client.containers.add(FakeContainer(name))
    BoxManager(client).start(_spec(), Path("/p"), "img", [], {})
    assert stale.removed


def test_started_box_executes_as_sandbox_user():
    client = FakeDocker()
    box = BoxManager(client).start(_spec(), Path("/p"), "img", [], {})
    box.executor.exec(["true"])
    container = client.containers.get(box.id)
    assert container.exec_calls == [(["true"], "bulbi")]


def test_stop_stops_and_removes_and_ignores_missing():
    client = FakeDocker()
    container = client.containers.add(FakeContainer("c"))
    manager = BoxManager(client)
    manager.stop(container.id)
    assert container.stopped and container.removed
    manager.stop("does-not-exist")


def test_list_boxes():
    client = FakeDocker()
    client.containers.add(FakeContainer("bulbi-demo-1", labels={"bulbi.box": "demo"}))
    assert BoxManager(client).list_boxes() == [
        BoxInfo(id="id-bul", name="bulbi-demo-1", box="demo", status="running")
    ]


def test_remove_missing_container_raises_sandbox_error():
    with pytest.raises(SandboxError, match="failed to remove container nope"):
        BoxManager(FakeDocker()).remove("nope")


def test_reset_removes_containers_and_images():
    client = FakeDocker(images={"bulbi/demo:1"})
    container = client.containers.add(FakeContainer("c"))
    BoxManager(client).reset()
    assert container.removed
    assert client.images.removed == ["bulbi/demo:1"]


def test_invalid_memory_limit_fails_before_docker_is_called():
    from bulbi.errors import SpecError

    client = FakeDocker()
    with pytest.raises(SpecError, match="invalid memory string"):
        BoxManager(client).start(_spec(limits=LimitsSpec(memory="lots")), Path("/p"), "i", [], {})
