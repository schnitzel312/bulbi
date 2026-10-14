"""Shared boxes, worktrees and secrets against real Docker, through the real CLI.

Spec §8.4 (multi-session), §9.6 (worktrees) and §10.5 (secrets), docker parts.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from bulbi.container.sessions import DockerSessionTracker
from tests.docker.conftest import box_name, write_spec
from tests.repos import add_worktree, git, make_repo

BULBI = str(Path(sys.executable).parent / "bulbi")


def bulbi(cwd: Path, *args: str, env: dict | None = None, timeout: float = 300):
    return subprocess.run(
        [BULBI, *args],
        check=False,
        cwd=cwd,
        capture_output=True,
        text=True,
        env={**os.environ, "COLUMNS": "250", **(env or {})},
        timeout=timeout,
    )


def spawn(cwd: Path, *args: str, env: dict | None = None) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [BULBI, *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, **(env or {})},
    )


def wait_for(condition: Callable[[], bool], timeout: float, interval: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return False


def containers(client, name: str) -> dict[str, object]:
    found = client.containers.list(all=True, filters={"label": f"bulbi.box={name}"})
    return {("gateway" if c.name.endswith("-gw") else "box"): c for c in found} | {
        "count": len(found)
    }


def sessions(client, name: str) -> int:
    box = containers(client, name).get("box")
    return DockerSessionTracker(client).active_sessions(box.id) if box else 0


# ---- §8.4 one shared box ---------------------------------------------------------------------


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "app")


def test_concurrent_runs_share_one_box_and_gateway_then_stop_with_idle_zero(
    docker_client, project
):
    name = box_name("share")
    write_spec(project, name, allow=["pypi.org"], idle="0")
    # Sessions hold until the test has seen both, however long cold image builds take.
    release = project / "release"
    hold = f"for i in $(seq 300); do [ -e {release} ] && exit 0; sleep 1; done; exit 1"
    first = spawn(project, "run", "--", "sh", "-c", hold)
    second = spawn(project, "run", "--", "sh", "-c", hold)
    try:
        assert wait_for(lambda: sessions(docker_client, name) == 2, timeout=280), containers(
            docker_client, name
        )
        found = containers(docker_client, name)
        assert found["count"] == 2  # exactly one box and one gateway
        listing = bulbi(project, "ls").stdout
        row = next(line for line in listing.splitlines() if found["box"].name in line)
        assert " 2 " in row
    finally:
        release.write_text("")
        first.wait(timeout=120)
        second.wait(timeout=120)
    assert first.returncode == second.returncode == 0, (first.stdout.read(), second.stdout.read())
    found = containers(docker_client, name)
    for role in ("box", "gateway"):
        found[role].reload()
        assert found[role].status == "exited", role  # stopped, and kept


def test_box_stops_itself_after_the_idle_timeout(docker_client, project):
    """A live session longer than the timeout keeps the box up; a process it leaves in the
    background does not (review MINOR-3)."""
    name = box_name("idle")
    write_spec(project, name, allow=["pypi.org"], idle="1m")
    session = "nohup sleep 600 >/dev/null 2>&1 & sleep 75; echo SESSION-DONE"
    result = bulbi(project, "run", "--", "sh", "-c", session)
    assert result.returncode == 0 and "SESSION-DONE" in result.stdout, (
        result.stdout + result.stderr
    )
    box = containers(docker_client, name)["box"]
    box.reload()
    assert box.status == "running"
    started = time.monotonic()
    assert wait_for(lambda: (box.reload(), box.status)[1] == "exited", timeout=150, interval=5)
    # The watcher checks every 30 s, so it stops within timeout +/- one check interval.
    assert 25 <= time.monotonic() - started <= 150


def test_spec_change_during_a_session_refuses_the_next_run(docker_client, project):
    name = box_name("edit")
    write_spec(project, name, allow=["pypi.org"], idle="0")
    running = spawn(project, "run", "--", "sleep", "20")
    try:
        assert wait_for(lambda: sessions(docker_client, name) == 1, timeout=240)
        write_spec(project, name, allow=["pypi.org", "example.com"], idle="0")
        result = bulbi(project, "run", "--", "true")
        assert result.returncode == 1
        assert "older spec with 1 active session" in result.stdout + result.stderr
        assert "bulbi restart" in result.stdout + result.stderr
    finally:
        running.wait(timeout=120)


# ---- §9.6 worktrees ---------------------------------------------------------------------------


def test_worktrees_share_one_box_with_their_own_cwd_and_can_commit(docker_client, tmp_path):
    repo = make_repo(tmp_path / "code" / "app")
    name = box_name("wt")
    write_spec(repo, name, allow=["pypi.org"], idle="0")
    git(repo, "add", "bulbi.toml")
    git(repo, "commit", "-q", "-m", "spec")
    trees = tmp_path / "trees"
    a = add_worktree(repo, trees / "a", "a")
    b = add_worktree(repo, trees / "b", "b")
    script = "pwd; sleep 15"
    one = spawn(a, "run", "--", "sh", "-c", script)
    two = spawn(b, "run", "--", "sh", "-c", script)
    try:
        assert wait_for(lambda: sessions(docker_client, name) == 2, timeout=240)
        assert containers(docker_client, name)["count"] == 2  # one box + one gateway
        # A worktree created after start in the dedicated dir works without a restart.
        late = add_worktree(repo, trees / "late", "late")
        result = bulbi(late, "run", "--", "pwd")
        assert result.returncode == 0 and str(late) in result.stdout, result.stdout + result.stderr
    finally:
        one.wait(timeout=120)
        two.wait(timeout=120)
    assert str(a) in one.stdout.read() and str(b) in two.stdout.read()

    commit = (
        "git -c user.name=t -c user.email=t@t commit -q --allow-empty -m from-box"
        " && git log -1 --format=%s"
    )
    for worktree in (a, b):
        result = bulbi(worktree, "run", "--", "sh", "-c", commit)
        assert result.returncode == 0 and "from-box" in result.stdout, (
            result.stdout + result.stderr
        )

    attacks = [
        f"echo evil > {repo}/.git/hooks/post-checkout",
        f"echo evil >> {repo}/bulbi.toml",
        f"echo evil >> {a}/bulbi.toml",
        f"echo evil >> {repo}/.git/config",
    ]
    for attack in attacks:
        result = bulbi(b, "run", "--", "sh", "-c", attack)
        assert result.returncode != 0, attack
        assert "Read-only" in result.stdout + result.stderr, attack


# ---- §10.5 secrets ----------------------------------------------------------------------------


def test_env_and_file_secrets_reach_sessions_and_rotate(docker_client, project, tmp_path):
    name = box_name("sec")
    token_file = tmp_path / "token.txt"
    token_file.write_text("file-v1")
    write_spec(
        project,
        name,
        allow=["pypi.org"],
        idle="10m",
        extra=(
            "[secrets]\n"
            'GITHUB_TOKEN = { from = "env", source = "BULBI_TEST_TOKEN" }\n'
            f'API_FILE = {{ from = "file", source = "{token_file}", to = "file", '
            'path = "~/.config/api/token" }\n'
        ),
    )
    show = (
        'echo "env=$GITHUB_TOKEN"; cat ~/.config/api/token; echo; stat -c %a ~/.config/api/token'
    )
    first = bulbi(project, "run", "--", "sh", "-c", show, env={"BULBI_TEST_TOKEN": "env-v1"})
    assert first.returncode == 0, first.stdout + first.stderr
    assert "env=env-v1" in first.stdout and "file-v1" in first.stdout and "600" in first.stdout
    log = project / ".bulbi" / "proxy.log"
    assert not log.exists() or "env-v1" not in log.read_text()

    token_file.write_text("file-v2")
    second = bulbi(project, "run", "--", "sh", "-c", show, env={"BULBI_TEST_TOKEN": "env-v2"})
    assert "env=env-v2" in second.stdout and "file-v2" in second.stdout, second.stdout
