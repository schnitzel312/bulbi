"""End-to-end CLI tests with click's CliRunner, fake Docker, and a fake `docker exec`."""

import json
from pathlib import Path
from textwrap import dedent

import docker
import docker.errors
import pytest
from click.testing import CliRunner, Result
from rich.console import Console

from bulbi.agents import AgentRegistry, ClaudeAgent, CodexAgent, NoCredentialProvider
from bulbi.cli import main
from bulbi.cli.context import AppContext
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.terminal import TerminalExec
from bulbi.errors import SandboxError
from bulbi.gateway.config import HostAccess
from bulbi.image import DockerfileBuilder, ImageBuilder
from bulbi.spec import SpecLoader
from bulbi.tools import ToolRegistry
from tests.fakes import FakeContainer, FakeDocker, RecordingRunner

SPEC = dedent("""\
    spec = "0.1"

    [box]
    name = "demo"
    agent = "claude"

    [tools]
    allow = ["python@3.12", "git"]

    [[mount]]
    path = "."

    [network]
    allow = ["pypi.org"]

    [profiles.offline]
    tools.allow = ["git"]
    network.allow = []
""")


def _tag_for(spec) -> str:
    builder = ImageBuilder(FakeDocker(), DockerfileBuilder(ToolRegistry.builtin()))
    return builder.tag_for(spec, ClaudeAgent(credentials=NoCredentialProvider()))


class Harness:
    """Runs the CLI against a temporary project with fakes for every external system."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.docker = FakeDocker()
        self.runner = RecordingRunner(returncode=0)
        self.docker_available = True

    def write_spec(self, text: str = SPEC) -> None:
        (self.project_root / "bulbi.toml").write_text(text)

    def _docker_factory(self) -> FakeDocker:
        if not self.docker_available:
            raise docker.errors.DockerException("socket not found")
        return self.docker

    def invoke(self, *args: str, input: str | None = None) -> Result:
        app = AppContext(
            project_root=self.project_root,
            console=Console(width=200),
            docker_factory=self._docker_factory,
            terminal=TerminalExec(runner=self.runner, is_terminal=lambda: False),
            environment=EnvironmentBuilder(host_env={}),
            host_access=HostAccess.DOCKER_DESKTOP,
            agents=AgentRegistry(
                [
                    ClaudeAgent(credentials=NoCredentialProvider(), host_home=self.project_root),
                    CodexAgent(),
                ]
            ),
        )
        return CliRunner().invoke(main, list(args), obj=app, input=input)

    @property
    def executed(self) -> list[list[str]]:
        """Commands passed to `docker exec`, without the docker/container prefix."""
        return [call[call.index("/entrypoint.sh") + 1 :] for call in self.runner.calls]


@pytest.fixture
def cli(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_help_lists_every_command(cli: Harness):
    result = cli.invoke("--help")
    assert result.exit_code == 0
    for name in ("init", "check", "run", "shell", "log", "ls", "rm", "reset"):
        assert f"  {name} " in result.output


# ---- init --------------------------------------------------------------------


def test_init_writes_starter_spec(cli: Harness):
    (cli.project_root / "go.mod").write_text("module x\n")
    result = cli.invoke("init")
    assert result.exit_code == 0
    assert "Wrote bulbi.toml" in result.output
    assert '"proxy.golang.org"' in (cli.project_root / "bulbi.toml").read_text()


def test_init_refuses_to_overwrite_without_force(cli: Harness):
    cli.write_spec("keep me")
    result = cli.invoke("init")
    assert result.exit_code == 1
    assert "already exists. Use --force to overwrite." in result.output
    assert (cli.project_root / "bulbi.toml").read_text() == "keep me"
    assert cli.invoke("init", "--force").exit_code == 0
    assert "[box]" in (cli.project_root / "bulbi.toml").read_text()


# ---- check -------------------------------------------------------------------


def test_check_summarises_spec_and_warnings(cli: Harness):
    cli.write_spec()
    result = cli.invoke("check")
    assert result.exit_code == 0
    assert "Box: demo  (agent: claude)" in result.output
    assert "pypi.org" in result.output
    assert "offline" in result.output
    assert "Warnings:" in result.output
    assert "interpreters allowed (python)" in result.output


def test_check_reports_errors(cli: Harness):
    cli.write_spec(SPEC.replace('"git"]', '"git", "cobol"]'))
    result = cli.invoke("check")
    assert "Errors:" in result.output
    assert "unknown tool: 'cobol'" in result.output


def test_check_without_spec_fails_cleanly(cli: Harness):
    result = cli.invoke("check")
    assert result.exit_code == 1
    assert "Error: no bulbi.toml found in" in result.output


# ---- run / shell -------------------------------------------------------------


def _containers(cli: Harness) -> list:
    return list(
        {id(c): c for c in cli.docker.containers.by_key.values() if not c.removed}.values()
    )


def test_run_launches_agent_and_leaves_the_shared_box_running(cli: Harness):
    cli.write_spec()
    cli.runner.returncode = 5
    result = cli.invoke("run")

    assert result.exit_code == 5
    assert "Building image for demo..." in result.output
    assert "Starting network gateway..." in result.output
    assert "Starting container..." in result.output
    assert "Running: claude --dangerously-skip-permissions" in result.output
    assert cli.executed == [["claude", "--dangerously-skip-permissions"]]
    assert len(cli.docker.box_builds) == 1
    containers = _containers(cli)
    assert len(containers) == 2  # box + gateway, kept for other sessions (idle_timeout 10m)
    assert all(container.status == "running" for container in containers)


def test_run_with_idle_timeout_zero_stops_box_and_gateway_after_the_session(cli: Harness):
    cli.write_spec(SPEC.replace('agent = "claude"', 'agent = "claude"\nidle_timeout = "0"'))
    assert cli.invoke("run").exit_code == 0
    containers = _containers(cli)
    assert len(containers) == 2
    assert all(container.status == "exited" for container in containers)


def test_second_run_attaches_to_the_same_box(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    result = cli.invoke("run", "--", "bash")
    assert "Starting container..." not in result.output
    assert len(cli.docker.containers.run_calls) == 2


def test_run_with_explicit_command_and_profile(cli: Harness):
    cli.write_spec()
    result = cli.invoke("run", "-p", "offline", "--", "pytest", "-q")
    assert result.exit_code == 0
    assert cli.executed == [["pytest", "-q"]]
    # The profile was applied: its narrower tool list is what got built into the image.
    (build,) = cli.docker.box_builds
    assert "python3" not in build["dockerfile"]
    assert build["tag"] != _tag_for(SpecLoader().load(cli.project_root))


def test_run_unknown_profile_fails_before_docker(cli: Harness):
    cli.write_spec()
    result = cli.invoke("run", "-p", "nope")
    assert result.exit_code == 1
    assert "Error: unknown profile: 'nope'" in result.output
    assert cli.docker.containers.run_calls == []


def test_run_reuses_cached_image(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    cli.invoke("run")
    assert len(cli.docker.box_builds) == 1


def test_shell_opens_bash(cli: Harness):
    cli.write_spec()
    result = cli.invoke("shell")
    assert result.exit_code == 0
    assert "Opening shell: bash" in result.output
    assert cli.executed == [["bash"]]


def test_docker_unavailable_is_a_clean_error(cli: Harness):
    cli.write_spec()
    cli.docker_available = False
    result = cli.invoke("shell")
    assert result.exit_code == 1
    assert "Error: Docker is not available: socket not found" in result.output


# ---- log ---------------------------------------------------------------------


def _write_log(project_root: Path, *entries: dict) -> None:
    log = project_root / ".bulbi" / "proxy.log"
    log.parent.mkdir()
    log.write_text("".join(json.dumps(entry) + "\n" for entry in entries))


ALLOWED = {"timestamp": "t1", "domain": "ok.com", "action": "allow", "method": "GET", "url": "u1"}
DENIED = {"timestamp": "t2", "domain": "bad.com", "action": "deny", "method": "GET", "url": "u2"}


def test_log_shows_entries_and_totals(cli: Harness):
    _write_log(cli.project_root, ALLOWED, DENIED)
    result = cli.invoke("log")
    assert result.exit_code == 0
    assert "ok.com" in result.output
    assert "bad.com" in result.output
    assert "2 total entries, 1 denied" in result.output


def test_log_denied_only(cli: Harness):
    _write_log(cli.project_root, ALLOWED, DENIED)
    result = cli.invoke("log", "--denied")
    assert "ok.com" not in result.output
    assert "bad.com" in result.output
    assert "2 total entries, 1 denied" in result.output


def test_log_missing_file(cli: Harness):
    result = cli.invoke("log")
    assert result.exit_code == 1
    assert "No log file found at" in result.output


def test_log_malformed_file(cli: Harness):
    (cli.project_root / ".bulbi").mkdir()
    (cli.project_root / ".bulbi" / "proxy.log").write_text("{oops\n")
    result = cli.invoke("log")
    assert result.exit_code == 1
    assert "Failed to parse log file" in result.output


# ---- ls / rm / reset ---------------------------------------------------------


def test_ls_without_containers(cli: Harness):
    result = cli.invoke("ls")
    assert result.exit_code == 0
    assert "No running bulbi containers." in result.output


def test_ls_lists_containers(cli: Harness):
    cli.docker.containers.add(FakeContainer("bulbi-demo-1", labels={"bulbi.box": "demo"}))
    result = cli.invoke("ls")
    assert "bulbi-demo-1" in result.output
    assert "running" in result.output


def test_rm_removes_container(cli: Harness):
    container = cli.docker.containers.add(FakeContainer("bulbi-demo-1"))
    result = cli.invoke("rm", "bulbi-demo-1")
    assert result.exit_code == 0
    assert "Removed container: bulbi-demo-1" in result.output
    assert container.removed


def test_rm_unknown_container_fails_cleanly(cli: Harness):
    result = cli.invoke("rm", "ghost")
    assert result.exit_code == 1
    assert "Error: failed to remove container ghost" in result.output


def test_reset_requires_confirmation(cli: Harness):
    container = cli.docker.containers.add(FakeContainer("c"))
    result = cli.invoke("reset", input="n\n")
    assert result.exit_code == 1
    assert "Aborted!" in result.output
    assert not container.removed


def test_reset_with_yes_removes_everything(cli: Harness):
    container = cli.docker.containers.add(FakeContainer("c"))
    cli.docker.images.tags.add("bulbi/demo:1")
    result = cli.invoke("reset", "--yes")
    assert result.exit_code == 0
    assert "All bulbi containers and images removed." in result.output
    assert container.removed
    assert cli.docker.images.removed == ["bulbi/demo:1"]


def test_image_tag_matches_spec_hash(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    expected = _tag_for(SpecLoader().load(cli.project_root))
    assert cli.docker.box_builds[0]["tag"] == expected


def test_run_with_profile_widening_network_default_fails_before_docker(cli: Harness):
    cli.write_spec(SPEC + '\n[profiles.open]\nnetwork.default = "allow"\n')
    result = cli.invoke("run", "-p", "open")
    assert result.exit_code == 1
    assert "profile widens network default from 'deny' to 'allow'" in result.output
    assert cli.docker.containers.run_calls == []


def test_importing_the_cli_does_not_load_the_docker_sdk():
    import subprocess
    import sys

    probe = "import sys, bulbi.cli; print('docker' in sys.modules)"
    output = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    ).stdout
    assert output.strip() == "False"


def test_default_docker_factory_errors_are_wrapped_once(tmp_path: Path, monkeypatch):
    def unavailable():
        raise docker.errors.DockerException("no socket")

    monkeypatch.setattr(docker, "from_env", unavailable)
    app = AppContext(project_root=tmp_path, console=Console(width=200))
    with pytest.raises(SandboxError) as excinfo:
        _ = app.docker
    assert str(excinfo.value) == "Docker is not available: no socket"


def test_check_prints_effective_policy_and_denies(cli: Harness):
    cli.write_spec(
        SPEC.replace(
            'allow = ["pypi.org"]',
            'allow = ["pypi.org", "host:5432", "10.20.0.0/16"]\ndeny = ["evil.pypi.org"]',
        )
    )
    result = cli.invoke("check")
    assert result.exit_code == 0
    assert (
        "Effective policy: Whitelist. Any protocol to 1 domain, host:5432, 10.20.0.0/16. "
        "Deny 1 rule. Local/private blocked unless listed." in result.output
    )
    assert "Deny" in result.output and "evil.pypi.org" in result.output
    assert "sharing a CDN address" in result.output


def test_check_describes_blacklist_mode(cli: Harness):
    cli.write_spec(
        SPEC.replace("[network]\n", '[network]\ndefault = "allow"\ndeny = ["example.com"]\n')
    )
    result = cli.invoke("check")
    assert (
        "Blacklist (best effort). Any protocol to any public destination except 1 rule."
        in result.output
    )


# ---- stop / restart / ls (spec §8.3) ------------------------------------------------------------


def _box(cli: Harness):
    return next(c for c in _containers(cli) if c.labels.get("bulbi.role") != "gateway")


def test_stop_stops_box_and_gateway_but_keeps_them(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    result = cli.invoke("stop")
    assert result.exit_code == 0 and "Stopped bulbi-demo-" in result.output
    assert all(c.status == "exited" and not c.removed for c in _containers(cli))


def test_stop_asks_before_ending_active_sessions(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    box = _box(cli)
    box.attrs["ExecIDs"] = ["s"]
    cli.docker.api.execs["s"] = {
        "Running": True,
        "ProcessConfig": {"entrypoint": "/entrypoint.sh"},
    }
    result = cli.invoke("stop", input="n\n")
    assert result.exit_code == 1 and "1 active session(s) will be ended" in result.output
    assert box.status == "running"
    assert cli.invoke("stop", "--yes").exit_code == 0
    assert box.status == "exited"


def test_stop_all_stops_every_box(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    cli.invoke("run", "-p", "offline")
    result = cli.invoke("stop", "--all")
    assert "Stopped 2 box(es)." in result.output
    assert all(c.status == "exited" for c in _containers(cli))


def test_restart_recreates_the_box_with_the_current_spec(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    old_hash = _box(cli).labels["bulbi.spec_hash"]
    cli.write_spec(SPEC.replace('allow = ["pypi.org"]', 'allow = ["pypi.org", "example.com"]'))
    result = cli.invoke("restart")
    assert result.exit_code == 0 and "Restarted bulbi-demo-" in result.output
    assert _box(cli).labels["bulbi.spec_hash"] != old_hash
    assert len(_containers(cli)) == 2


def test_run_after_spec_change_with_live_session_is_refused(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    box = _box(cli)
    box.attrs["ExecIDs"] = ["s"]
    cli.docker.api.execs["s"] = {
        "Running": True,
        "ProcessConfig": {"entrypoint": "/entrypoint.sh"},
    }
    cli.write_spec(SPEC.replace('allow = ["pypi.org"]', 'allow = ["pypi.org", "example.com"]'))
    result = cli.invoke("run")
    assert result.exit_code == 1
    assert (
        "box is running an older spec with 1 active session; finish them or run `bulbi restart`"
        in result.output
    )


def test_ls_shows_project_profile_state_and_sessions(cli: Harness):
    cli.write_spec()
    cli.invoke("run")
    box = _box(cli)
    box.attrs["ExecIDs"] = ["s"]
    cli.docker.api.execs["s"] = {
        "Running": True,
        "ProcessConfig": {"entrypoint": "/entrypoint.sh"},
    }
    result = cli.invoke("ls")
    assert box.name in result.output
    assert str(cli.project_root.resolve()) in result.output
    assert "running" in result.output
    assert "-gw" not in result.output  # gateways stay hidden
    row = next(line for line in result.output.splitlines() if box.name in line)
    assert " 1 " in row


def test_format_uptime():
    from datetime import UTC, datetime

    from bulbi.cli.commands.ls import format_uptime

    now = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    assert format_uptime("2026-01-01T10:55:00Z", now) == "1h 05m"
    assert format_uptime("2026-01-01T10:55:00.123456789Z", now) == "1h 04m"
    assert format_uptime("2026-01-01T11:58:00Z", now) == "2m"
    assert format_uptime(None, now) == "-"
    assert format_uptime("garbage", now) == "-"


def test_run_from_worktree_uses_main_spec_and_warns_when_its_copy_differs(tmp_path: Path):
    from tests.repos import add_worktree, make_repo

    repo = make_repo(tmp_path / "app")
    (repo / "bulbi.toml").write_text(SPEC)
    wt = add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    (wt / "bulbi.toml").write_text(SPEC.replace('allow = ["pypi.org"]', 'allow = ["evil.test"]'))
    harness = Harness(wt)
    result = harness.invoke("run")
    assert result.exit_code == 0
    assert "This worktree's bulbi.toml differs from the main checkout's" in result.output
    gateway_env = harness.docker.containers.run_calls[0][1]["environment"]
    assert "evil.test" not in gateway_env["BULBI_GATEWAY_CONFIG"]
    assert "pypi.org" in gateway_env["BULBI_GATEWAY_CONFIG"]
    assert harness.runner.calls[0][harness.runner.calls[0].index("-w") + 1] == str(wt)


# ---- check exit code and pre-flight validation ----------------------------------------------

ERROR_SPEC = SPEC.replace('"git"]', '"git", "cobol"]')


def test_check_exits_1_when_validation_finds_errors(cli: Harness):
    cli.write_spec(ERROR_SPEC)
    result = cli.invoke("check")
    assert result.exit_code == 1
    assert "Errors:" in result.output and "✗ unknown tool: 'cobol'" in result.output
    assert "Box: demo" in result.output  # the full report is still printed


def test_check_exits_0_with_warnings_only(cli: Harness):
    cli.write_spec()
    result = cli.invoke("check")
    assert result.exit_code == 0
    assert "Warnings:" in result.output and "Errors:" not in result.output


@pytest.mark.parametrize("command", [["run"], ["shell"]])
def test_validation_errors_block_run_and_shell_before_anything_starts(cli: Harness, command):
    cli.write_spec(ERROR_SPEC)
    result = cli.invoke(*command)
    assert result.exit_code == 1
    assert "Errors:" in result.output and "✗ unknown tool: 'cobol'" in result.output
    assert cli.docker.images.builds == []
    assert cli.docker.containers.run_calls == []
    assert cli.runner.calls == []


def test_profile_is_resolved_before_validation(cli: Harness):
    # The root spec allows an interpreter (a warning); the profile narrows tools to git only.
    cli.write_spec()
    result = cli.invoke("run", "-p", "offline")
    assert result.exit_code == 0
    assert "interpreters allowed" not in result.output


def test_warnings_are_shown_but_do_not_block(cli: Harness):
    cli.write_spec()
    result = cli.invoke("run")
    assert result.exit_code == 0
    assert "Warnings:" in result.output and "interpreters allowed (python)" in result.output
    assert "Spec is valid" not in result.output
    assert cli.runner.calls
