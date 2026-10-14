"""Git safety against real Docker, through the real CLI (docs/specs/git-safety.md §5).

From inside the box the agent tries vectors A (repoint a worktree's ``.git`` file),
B (rewrite a worktree's ``commondir``) and C (plant a new ``.git`` pointing at a gitdir
whose config runs an ``fsmonitor`` hook). Afterwards the *host* runs ``git status``, as
the user would; a PWNED marker means code ran on the host. Both git modes are covered.
Throwaway repositories only; each test removes the box, gateway, network and clone
volume it created.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import docker.errors
import pytest

from tests.docker.conftest import box_name, write_spec
from tests.docker.test_lifecycle import bulbi
from tests.repos import add_worktree, git, make_repo

IDENTITY = "-c user.name=Agent -c user.email=agent@bulbi.invalid"


@dataclass
class Project:
    mode: str
    repo: Path
    worktree: Path
    tmp: Path

    def in_box(self, script: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        """One `bulbi run` session; the git safety scan runs when it ends."""
        return bulbi(cwd or self.worktree, "run", "--", "bash", "-c", script)

    def evil_gitdir(self, marker: Path) -> tuple[str, Path]:
        """A script planting, from inside the box, a gitdir whose config runs a hook on
        host `git status`; and that gitdir. Attacks run in the same session, before the
        session-end scan."""
        at, hook = self.worktree / "evil", self.worktree / "pwn.sh"
        script = (
            f"git init -q {at} && "
            f"printf '#!/bin/sh\\ntouch {marker}\\nexit 1\\n' > {hook} && chmod +x {hook} && "
            f"git -C {at} config core.fsmonitor {hook} && "
            f"git -C {at} config core.worktree {self.worktree} && "
        )
        return script, at / ".git"


def _host_git_status(cwd: Path) -> None:
    subprocess.run(["git", "status"], cwd=cwd, capture_output=True, check=False)


def _remove_box(client, repo: Path) -> None:
    project = str(repo / ".git")
    found = client.containers.list(all=True, filters={"label": f"bulbi.project={project}"})
    found.sort(key=lambda c: c.name.endswith("-gw"))
    names = {c.name.removesuffix("-gw") for c in found}
    for container in found:
        container.remove(force=True)
    for name in names:
        for network in client.networks.list(names=[f"{name}-net"]):
            network.remove()
    for volume in client.volumes.list(filters={"label": f"bulbi.project={project}"}):
        volume.remove(force=True)


@pytest.fixture(params=["guarded", "isolated"])
def project(request, docker_client, tmp_path: Path) -> Iterator[Project]:
    repo = make_repo(tmp_path / "code" / "app")
    write_spec(
        repo,
        box_name("gitsafety"),
        allow=["pypi.org"],
        extra=f'[git]\nmode = "{request.param}"\n',
    )
    git(repo, "add", "bulbi.toml")
    git(repo, "commit", "-q", "-m", "spec")
    worktree = add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    yield Project(request.param, repo, worktree, tmp_path)
    # Whatever is left is removed by the session fixture.
    with suppress(docker.errors.DockerException):
        _remove_box(docker_client, repo)


def test_vector_a_repointing_the_worktree_git_file_is_refused(project):
    marker = project.tmp / "PWNED_A"
    plant, evil = project.evil_gitdir(marker)
    result = project.in_box(f"{plant} echo 'gitdir: {evil}' > {project.worktree}/.git")
    assert result.returncode != 0 and "Read-only" in result.stderr + result.stdout
    _host_git_status(project.worktree)
    assert not marker.exists(), "host git executed agent-controlled code"


def test_vector_b_rewriting_commondir_never_reaches_the_host(project):
    marker = project.tmp / "PWNED_B"
    plant, evil = project.evil_gitdir(marker)
    commondir = project.repo / ".git" / "worktrees" / "wt" / "commondir"
    before = commondir.read_text()
    result = project.in_box(f"{plant} echo '{evil}' > {commondir}")
    if project.mode == "guarded":
        assert result.returncode != 0 and "Read-only" in result.stderr + result.stdout
    else:  # The box writes its own clone's admin dir; the host's is not even mounted.
        assert result.returncode == 0, result.stdout + result.stderr
    assert commondir.read_text() == before
    _host_git_status(project.worktree)
    assert not marker.exists(), "host git executed agent-controlled code"


def test_vector_c_is_quarantined_when_the_session_ends(project):
    marker = project.tmp / "PWNED_C"
    src = project.worktree / "src"
    src.mkdir()
    plant, evil = project.evil_gitdir(marker)
    result = project.in_box(f"{plant} echo 'gitdir: {evil}' > {src}/.git")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Git safety" in result.stdout and "bulbi git-restore" in result.stdout

    assert not (src / ".git").exists() and not evil.exists()
    _host_git_status(src)
    _host_git_status(project.worktree / "evil")
    assert not marker.exists(), "host git executed agent-controlled code"
    assert any((project.repo / ".bulbi" / "quarantine").glob("*.json"))
    scan = bulbi(project.repo, "git-scan")
    assert scan.returncode == 0 and "No dangerous git metadata" in scan.stdout


def test_worktree_created_in_the_box_cannot_be_turned_against_the_host(project):
    """Review: a worktree added after box start has writable pointer files."""
    if project.mode == "isolated":
        pytest.skip("in isolated mode in-box worktrees live in the box's clone")
    marker = project.tmp / "PWNED_LATE"
    trees = project.worktree.parent
    kept = project.in_box(f"git -C {project.worktree} worktree add -q {trees / 'ok'} -b ok")
    assert kept.returncode == 0, kept.stdout + kept.stderr
    assert (trees / "ok" / ".git").is_file(), "a legitimate in-box worktree is kept"
    assert subprocess.run(["git", "status"], cwd=trees / "ok", check=False).returncode == 0

    plant, evil = project.evil_gitdir(marker)
    late = trees / "late"
    script = (
        f"{plant} git -C {project.worktree} worktree add -q {late} -b late && "
        f"echo 'gitdir: {evil}' > {late}/.git"
    )
    result = project.in_box(script)
    assert result.returncode == 0, result.stdout + result.stderr
    _host_git_status(late)
    assert not marker.exists(), "host git executed agent-controlled code"


def test_isolated_box_commits_come_back_with_bulbi_pull(project):
    if project.mode == "guarded":
        pytest.skip("guarded boxes commit straight into the host repository")
    host_only = project.repo / ".git" / "host-only"
    host_only.write_text("x")
    script = (
        f"test ! -e {host_only} && "
        f"echo work > agent.txt && git add agent.txt && git {IDENTITY} commit -q -m 'agent work'"
    )
    result = project.in_box(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert git(project.repo, "log", "-1", "--format=%s", "wt") == "spec"

    pulled = bulbi(project.repo, "pull", "--branch", "wt")
    assert pulled.returncode == 0, pulled.stdout + pulled.stderr
    assert "bulbi/wt" in pulled.stdout
    assert git(project.repo, "log", "-1", "--format=%s", "bulbi/wt") == "agent work"
    assert git(project.repo, "log", "-1", "--format=%s", "wt") == "spec"
