"""End-to-end CLI tests with click's CliRunner, fake Docker, and a fake `docker exec`."""

import json
from pathlib import Path
from textwrap import dedent

import docker.errors
import pytest
from click.testing import CliRunner, Result
from rich.console import Console

from bulbi.agents import AgentRegistry, ClaudeAgent, CodexAgent, NoCredentialProvider
from bulbi.cli import main
from bulbi.cli.context import AppContext
from bulbi.container.environment import EnvironmentBuilder
from bulbi.container.terminal import TerminalExec
from bulbi.image import ImageBuilder
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
    network.allow = []
""")


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
            environment=EnvironmentBuilder(host_env={}, system="Darwin"),
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


def test_run_launches_agent_and_cleans_up(cli: Harness):
    cli.write_spec()
    cli.runner.returncode = 5
    result = cli.invoke("run")

    assert result.exit_code == 5
    assert "Building image for demo..." in result.output
    assert "Starting container..." in result.output
    assert "Running: claude --dangerously-skip-permissions" in result.output
    assert cli.executed == [["claude", "--dangerously-skip-permissions"]]
    assert len(cli.docker.images.builds) == 1
    (container,) = {id(c): c for c in cli.docker.containers.by_key.values()}.values()
    assert container.removed


def test_run_with_explicit_command_and_profile(cli: Harness):
    cli.write_spec()
    result = cli.invoke("run", "-p", "offline", "--", "pytest", "-q")
    assert result.exit_code == 0
    assert cli.executed == [["pytest", "-q"]]


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
    assert len(cli.docker.images.builds) == 1


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
    from bulbi.spec import SpecLoader

    cli.write_spec()
    cli.invoke("run")
    expected = ImageBuilder.tag_for(SpecLoader().load(cli.project_root))
    assert cli.docker.images.builds[0]["tag"] == expected
