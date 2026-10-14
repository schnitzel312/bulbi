"""Git host-code-execution escapes (Phase 2 review B1, vectors A and B).

From inside the box the agent prepares a gitdir whose config runs a ``core.fsmonitor``
hook, then tries to point the host's git at it. Afterwards the *host* runs ``git status``
in the worktree, as the user would; a PWNED marker means code ran on the host.
Throwaway repositories only.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from bulbi.cli.context import AppContext
from tests.docker.conftest import box_name, write_spec
from tests.repos import add_worktree, git, make_repo


@dataclass
class Setup:
    repo: Path
    worktree: Path
    container: object

    def sh(self, command: str) -> tuple[int, str]:
        result = self.container.exec_run(["bash", "-c", command], user="bulbi")  # type: ignore[attr-defined]
        return result.exit_code, result.output.decode(errors="replace")


@pytest.fixture
def setup(docker_client, tmp_path: Path) -> Iterator[Setup]:
    repo = make_repo(tmp_path / "code" / "app")
    write_spec(repo, box_name("git"), allow=["pypi.org"], idle="10m")
    git(repo, "add", "bulbi.toml")
    git(repo, "commit", "-q", "-m", "spec")
    worktree = add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    app = AppContext(project_root=worktree)
    box = app.orchestrator(app.load_spec()).ensure()
    yield Setup(repo, worktree, docker_client.containers.get(box.id))


def _plant_evil_gitdir(setup: Setup, marker: Path) -> Path:
    """An agent-controlled gitdir (inside the writable worktree) that runs a hook."""
    evil = setup.worktree / "evil-gitdir"
    hook = evil / "pwn.sh"
    script = (
        f"cp -r {setup.repo}/.git {evil} && rm -rf {evil}/worktrees && "
        f"printf '#!/bin/sh\\ntouch {marker}\\nexit 1\\n' > {hook} && chmod +x {hook} && "
        f"git config --file {evil}/config core.fsmonitor {hook} && "
        f"git config --file {evil}/config core.bare false && "
        f"git config --file {evil}/config core.worktree {setup.worktree}"
    )
    code, output = setup.sh(script)
    assert code == 0, output
    return evil


def _host_git_status(worktree: Path) -> None:
    subprocess.run(["git", "status"], cwd=worktree, capture_output=True, check=False)


def test_vector_a_repointing_the_worktree_git_file_is_refused(setup):
    marker = setup.worktree.parent / "PWNED_A"
    evil = _plant_evil_gitdir(setup, marker)
    code, output = setup.sh(f"echo 'gitdir: {evil}' > {setup.worktree}/.git")
    assert code != 0 and "Read-only" in output, output
    _host_git_status(setup.worktree)
    assert not marker.exists(), "host git executed agent-controlled code"


def test_vector_b_rewriting_commondir_is_refused(setup):
    marker = setup.worktree.parent / "PWNED_B"
    evil = _plant_evil_gitdir(setup, marker)
    commondir = setup.repo / ".git" / "worktrees" / "wt" / "commondir"
    code, output = setup.sh(f"echo '{evil}' > {commondir}")
    assert code != 0 and "Read-only" in output, output
    _host_git_status(setup.worktree)
    assert not marker.exists(), "host git executed agent-controlled code"


def test_worktree_admin_gitdir_is_read_only(setup):
    gitdir = setup.repo / ".git" / "worktrees" / "wt" / "gitdir"
    code, output = setup.sh(f"echo /tmp/elsewhere > {gitdir}")
    assert code != 0 and "Read-only" in output, output
