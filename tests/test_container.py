"""Tests for mount planning, the box manager, session tracking and the terminal exec."""

from pathlib import Path

import pytest

from bulbi.container.identity import BoxIdentity
from bulbi.container.manager import BoxLaunch, BoxManager, ContainerState
from bulbi.container.mounts import BindMount, MountPlanner, TmpfsMount, is_worktree_container
from bulbi.container.sessions import DockerSessionTracker
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError, SpecError
from bulbi.project import Project, ProjectLocator
from bulbi.spec import BoxSpec, BulbiSpec, LimitsSpec, MountSpec, ProjectSpec, ToolsSpec
from tests.fakes import FakeContainer, FakeDocker, RecordingRunner
from tests.repos import add_worktree, make_repo

WORKSPACE = "/home/bulbi/workspace"


PROJECT_MOUNT = (MountSpec(path="."),)


def _spec(mounts=PROJECT_MOUNT, limits=None, worktree_dirs=(), idle="10m") -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo", idle_timeout=idle),
        tools=ToolsSpec(),
        mounts=list(mounts),
        limits=limits or LimitsSpec(),
        project=ProjectSpec(worktree_dirs=list(worktree_dirs)),
    )


def _binds(plan) -> list[tuple[str, str, bool]]:
    return [(m.source, m.target, m.read_only) for m in plan if isinstance(m, BindMount)]


# ---- MountPlanner: plain projects ------------------------------------------------------


def test_plain_project_is_mounted_at_its_host_path(tmp_path: Path):
    plan = MountPlanner(Project.plain(tmp_path)).plan(_spec())
    root = str(tmp_path.resolve())
    assert plan == [BindMount(root, root, read_only=False)]


def test_other_mounts_keep_their_workspace_target(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    plan = MountPlanner(Project.plain(tmp_path)).plan(
        _spec([MountSpec(path=str(docs), mode="read-only")])
    )
    assert plan == [BindMount(str(docs.resolve()), f"{WORKSPACE}/docs", read_only=True)]


def test_excluded_files_are_masked_and_directories_get_a_tmpfs(tmp_path: Path):
    (tmp_path / ".env").write_text("SECRET=1")
    (tmp_path / "secrets").mkdir()
    spec = _spec([MountSpec(path=".", exclude=[".env", "secrets", "*.key"])])
    root = str(tmp_path.resolve())
    plan = MountPlanner(Project.plain(tmp_path)).plan(spec)
    assert BindMount("/dev/null", f"{root}/.env", True) in plan
    assert TmpfsMount(f"{root}/secrets") in plan


def test_spec_file_is_mounted_read_only(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text("")
    spec_file = str(tmp_path.resolve() / "bulbi.toml")
    assert BindMount(spec_file, spec_file, True) in MountPlanner(Project.plain(tmp_path)).plan(
        _spec()
    )


def test_without_a_project_mount_nothing_of_the_project_is_mounted(tmp_path: Path):
    (tmp_path / "bulbi.toml").write_text("")
    assert MountPlanner(Project.plain(tmp_path)).plan(_spec(mounts=())) == []


# ---- MountPlanner: git worktrees (spec §9.2, §9.3) ----------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "code" / "app")


def _project(cwd: Path) -> Project:
    return ProjectLocator().locate(cwd)


def test_dedicated_worktree_parent_is_mounted_whole(tmp_path, repo):
    worktrees = tmp_path / "worktrees" / "app"
    a = add_worktree(repo, worktrees / "a", "a")
    add_worktree(repo, worktrees / "b", "b")
    planner = MountPlanner(_project(a))
    assert planner.checkout_roots(_spec()) == [repo, worktrees.resolve()]
    binds = _binds(planner.plan(_spec()))
    assert (str(worktrees.resolve()), str(worktrees.resolve()), False) in binds


def test_scattered_worktrees_are_mounted_individually_never_their_mixed_parent(tmp_path, repo):
    (tmp_path / "code" / "unrelated").mkdir()
    sibling = add_worktree(repo, tmp_path / "code" / "app-feature", "feature")
    roots = MountPlanner(_project(repo)).checkout_roots(_spec())
    assert roots == [repo, sibling]
    assert (tmp_path / "code").resolve() not in roots


def test_parent_holding_the_main_checkout_is_never_mounted(tmp_path, repo):
    sibling = add_worktree(repo, tmp_path / "code" / "app-wt", "wt")
    assert MountPlanner(_project(repo)).checkout_roots(_spec()) == [repo, sibling]


def test_worktree_dirs_are_mounted_whole(tmp_path, repo):
    dedicated = tmp_path / "trees"
    add_worktree(repo, dedicated / "x", "x")
    spec = _spec(worktree_dirs=[str(dedicated)])
    assert MountPlanner(_project(repo)).checkout_roots(spec) == [repo, dedicated.resolve()]


def test_worktree_dirs_with_foreign_entries_are_refused(tmp_path, repo):
    dedicated = tmp_path / "trees"
    add_worktree(repo, dedicated / "x", "x")
    (dedicated / "notes.txt").write_text("")
    with pytest.raises(SpecError, match="contains more than worktrees"):
        MountPlanner(_project(repo)).plan(_spec(worktree_dirs=[str(dedicated)]))


def test_protected_files_are_read_only_in_every_checkout(tmp_path, repo):
    (repo / "bulbi.toml").write_text("")
    wt = add_worktree(repo, tmp_path / "worktrees" / "app" / "wt", "wt")
    (wt / "bulbi.toml").write_text("")
    git_dir = repo / ".git"
    (git_dir / "worktrees" / "wt" / "config.worktree").write_text("")
    plan = MountPlanner(_project(wt)).plan(_spec())
    binds = _binds(plan)
    for path in (repo / "bulbi.toml", wt / "bulbi.toml", git_dir / "config", git_dir / "hooks",
                 git_dir / "worktrees" / "wt" / "config.worktree"):  # fmt: skip
        assert (str(path), str(path), True) in binds, path
    assert not any(".git-main" in target for _, target, _ in binds)


def test_missing_hooks_directory_is_hidden_by_an_empty_tmpfs(repo):
    hooks = repo / ".git" / "hooks"
    for hook in hooks.iterdir():
        hook.unlink()
    hooks.rmdir()
    assert TmpfsMount(str(hooks)) in MountPlanner(_project(repo)).plan(_spec())


def test_excludes_apply_to_every_worktree(tmp_path, repo):
    wt = add_worktree(repo, tmp_path / "worktrees" / "app" / "wt", "wt")
    (wt / ".env").write_text("SECRET=1")
    plan = MountPlanner(_project(repo)).plan(_spec([MountSpec(path=".", exclude=[".env"])]))
    assert BindMount("/dev/null", str(wt / ".env"), True) in plan


def test_is_worktree_container(tmp_path, repo):
    trees = tmp_path / "trees"
    wt = add_worktree(repo, trees / "one", "one")
    assert is_worktree_container(trees, [repo, wt])
    (trees / ".DS_Store").write_text("")
    assert is_worktree_container(trees, [repo, wt])
    (trees / "other").mkdir()
    assert not is_worktree_container(trees, [repo, wt])
    assert not is_worktree_container(tmp_path / "missing", [repo])


# ---- TerminalExec ----------------------------------------------------------------------


@pytest.mark.parametrize(("is_tty", "flags"), [(True, ["-it"]), (False, [])])
def test_terminal_exec_runs_through_entrypoint_in_the_workdir(is_tty: bool, flags: list[str]):
    runner = RecordingRunner(returncode=3)
    terminal = TerminalExec(runner=runner, is_terminal=lambda: is_tty)
    code = terminal.run(
        "cid", ["ls", "-la"], workdir="/repo/wt", environment={"BULBI_EXEC": "session"}
    )
    assert code == 3
    assert runner.calls == [
        ["docker", "exec", *flags, "-w", "/repo/wt", "-e", "BULBI_EXEC=session", "cid",
         "/entrypoint.sh", "ls", "-la"]
    ]  # fmt: skip


# ---- Identity --------------------------------------------------------------------------


def test_identity_names_and_labels(tmp_path):
    identity = BoxIdentity(tmp_path / ".git", "demo", "read only")
    assert identity.name.startswith("bulbi-demo-")
    assert identity.name.endswith("-read_only")
    assert identity.gateway_name == identity.name + "-gw"
    assert identity.network_name == identity.name + "-net"
    labels = identity.labels("abc", gateway=True)
    assert labels["bulbi.project"] == str(tmp_path / ".git")
    assert labels["bulbi.profile"] == "read only"
    assert labels["bulbi.spec_hash"] == "abc"
    assert labels["bulbi.role"] == "gateway"


def test_profiles_map_to_distinct_boxes(tmp_path):
    names = {BoxIdentity(tmp_path, "demo", profile).name for profile in (None, "a", "b")}
    assert len(names) == 3


# ---- BoxManager ------------------------------------------------------------------------


def _launch(tmp_path: Path, spec: BulbiSpec | None = None) -> BoxLaunch:
    return BoxLaunch(
        identity=BoxIdentity(tmp_path, "demo"),
        spec=spec or _spec(limits=LimitsSpec(cpu=3, memory="512MB")),
        image_tag="img:1",
        spec_hash="h1",
        mounts=[BindMount("/src", "/src", False), TmpfsMount("/src/secrets")],
        environment={"A": "1"},
        gateway_id="gw-id",
        project_root=tmp_path,
        worktrees=[tmp_path],
    )


def test_create_runs_a_hardened_box_in_the_gateway_namespace(tmp_path):
    client = FakeDocker()
    box = BoxManager(client).create(_launch(tmp_path))
    ((image, kwargs),) = client.containers.run_calls
    assert image == "img:1"
    assert box.id == f"id-{kwargs['name']}"
    assert kwargs["command"] == ["/usr/local/bin/bulbi-idle-watcher", "600"]
    assert kwargs["network_mode"] == "container:gw-id"
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges"]
    assert kwargs["pids_limit"] == 512
    assert kwargs["labels"]["bulbi.spec_hash"] == "h1"
    assert kwargs["labels"]["bulbi.worktrees"] == f'["{tmp_path}"]'
    assert kwargs["environment"] == {"A": "1", "BULBI_PROJECT_DIR": str(tmp_path)}
    assert kwargs["nano_cpus"] == 3 * 10**9
    assert kwargs["mem_limit"] == 512 * 1024**2
    assert kwargs["mounts"][1]["Type"] == "tmpfs"
    assert kwargs["mounts"][1]["ReadOnly"] is True


def test_stop_keeps_the_box_and_start_reuses_it(tmp_path):
    client = FakeDocker()
    manager = BoxManager(client)
    box = manager.create(_launch(tmp_path))
    manager.stop(box.id)
    container = client.containers.get(box.id)
    assert container.stopped and not container.removed
    assert manager.start(box.id).id == box.id
    manager.stop("does-not-exist")


def test_find_reports_state_and_labels(tmp_path):
    client = FakeDocker()
    manager = BoxManager(client)
    box = manager.create(_launch(tmp_path))
    state = manager.find(BoxIdentity(tmp_path, "demo").name)
    assert state is not None and state.id == box.id and state.running
    assert state.spec_hash == "h1"
    assert state.worktrees_at_start == [str(tmp_path)]
    assert manager.find("nope") is None


def test_list_boxes_hides_gateways():
    client = FakeDocker()
    client.containers.add(FakeContainer("bulbi-demo-1", labels={"bulbi.box": "demo"}))
    client.containers.add(FakeContainer("bulbi-demo-1-gw", labels={"bulbi.role": "gateway"}))
    assert [s.name for s in BoxManager(client).list_boxes()] == ["bulbi-demo-1"]
    assert len(BoxManager(client).list_containers()) == 2


def test_remove_box_also_removes_its_gateway_and_network():
    client = FakeDocker()
    box = client.containers.add(FakeContainer("bulbi-demo-1", labels={"bulbi.project": "/p"}))
    gateway = client.containers.add(
        FakeContainer("bulbi-demo-1-gw", labels={"bulbi.role": "gateway"})
    )
    network = client.networks.create("bulbi-demo-1-net", "bridge", {}, True)
    BoxManager(client).remove_box("bulbi-demo-1")
    assert box.removed and gateway.removed and network.removed


def test_remove_missing_container_raises_sandbox_error():
    with pytest.raises(SandboxError, match="failed to remove container nope"):
        BoxManager(FakeDocker()).remove_box("nope")


def test_reset_removes_boxes_before_gateways_then_networks_and_images():
    client = FakeDocker(images={"bulbi/demo:1"})
    removed: list[str] = []
    for name, labels in (("gw", {"bulbi.role": "gateway"}), ("box", {})):
        container = client.containers.add(FakeContainer(name, labels=labels))
        container.remove = lambda force=False, n=name: removed.append(n)  # type: ignore[method-assign]
    network = client.networks.create("bulbi-x-net", "bridge", {}, True)
    BoxManager(client).reset()
    assert removed == ["box", "gw"]
    assert network.removed
    assert client.images.removed == ["bulbi/demo:1"]


def test_invalid_memory_limit_fails_before_docker_is_called(tmp_path):
    client = FakeDocker()
    with pytest.raises(SpecError, match="invalid memory string"):
        BoxManager(client).create(_launch(tmp_path, _spec(limits=LimitsSpec(memory="lots"))))
    assert client.containers.run_calls == []


# ---- Session tracking ------------------------------------------------------------------


def test_session_count_ignores_setup_execs_and_finished_sessions():
    client = FakeDocker()
    box = client.containers.add(FakeContainer("box"))
    box.attrs["ExecIDs"] = ["s1", "s2", "setup", "done"]
    client.api.execs = {
        "s1": {"Running": True, "ProcessConfig": {"entrypoint": "/entrypoint.sh"}},
        "s2": {"Running": True, "ProcessConfig": {"entrypoint": "/entrypoint.sh"}},
        "setup": {"Running": True, "ProcessConfig": {"entrypoint": "claude"}},
        "done": {"Running": False, "ProcessConfig": {"entrypoint": "/entrypoint.sh"}},
    }
    assert DockerSessionTracker(client).active_sessions(box.id) == 2
    assert DockerSessionTracker(client).active_sessions("missing") == 0


def test_container_state_of_unknown_labels():
    state = ContainerState("id", "n", "exited", {"bulbi.worktrees": "not json"})
    assert not state.running
    assert state.worktrees_at_start == []


def test_remove_network_retries_while_an_endpoint_is_still_detaching():
    import docker.errors

    from bulbi.container.gateway import GatewayManager

    client = FakeDocker()
    network = client.networks.create("bulbi-x-net", "bridge", {}, True)
    attempts = []
    real_remove = network.remove

    def flaky_remove():
        attempts.append(1)
        if len(attempts) < 3:
            raise docker.errors.APIError("network has active endpoints")
        real_remove()

    network.remove = flaky_remove  # type: ignore[method-assign]
    GatewayManager(client, clock=lambda: 0.0, sleep=lambda _: None).remove_network(network.id)
    assert network.removed and len(attempts) == 3


def test_worktree_git_pointers_are_read_only_review_b1(tmp_path, repo):
    """Review B1 vectors A and B: a writable worktree `.git` file or admin `commondir` /
    `gitdir` lets the agent repoint git at a config it controls (host code execution)."""
    wt = add_worktree(repo, tmp_path / "worktrees" / "app" / "wt", "wt")
    admin = repo / ".git" / "worktrees" / "wt"
    binds = _binds(MountPlanner(_project(repo)).plan(_spec()))
    for path in (wt / ".git", admin / "commondir", admin / "gitdir"):
        assert (str(path), str(path), True) in binds, path


def test_reap_removes_gateways_of_removed_boxes_and_stops_those_of_stopped_boxes():
    """Review MINOR-1: a gateway whose box was removed used to linger until reset."""
    from bulbi.container.gateway import GatewayManager

    client = FakeDocker()
    stopped_box = client.containers.add(FakeContainer("bulbi-a-1"))
    stopped_box.status = "exited"
    kept_gateway = client.containers.add(
        FakeContainer("bulbi-a-1-gw", labels={"bulbi.role": "gateway"})
    )
    orphan_gateway = client.containers.add(
        FakeContainer("bulbi-b-2-gw", labels={"bulbi.role": "gateway"})
    )
    orphan_network = client.networks.create("bulbi-b-2-net", "bridge", {}, True)
    manager = GatewayManager(client, clock=lambda: 0.0, sleep=lambda _: None)

    manager.reap(BoxManager(client).list_containers())

    assert kept_gateway.status == "exited" and not kept_gateway.removed
    assert orphan_gateway.removed and orphan_network.removed
