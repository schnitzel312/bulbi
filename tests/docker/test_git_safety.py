"""Git safety against real Docker, through the real CLI (docs/specs/git-safety.md §5).

From inside the box the agent tries vectors A (repoint a worktree's ``.git`` file),
B (rewrite a worktree's ``commondir``) and C (plant a new ``.git`` pointing at a gitdir
whose config runs an ``fsmonitor`` hook). Afterwards the *host* runs ``git status``, as
the user would; a PWNED marker means code ran on the host. Both git modes are covered.
Throwaway repositories only; each test removes the box, gateway, network and clone
volume it created.
"""

from __future__ import annotations

import os
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


def _make_project(client, tmp_path: Path, mode: str, prepare=None) -> Iterator[Project]:
    repo = make_repo(tmp_path / "code" / "app")
    if prepare is not None:
        prepare(repo)
    write_spec(repo, box_name("gitsafety"), allow=["pypi.org"], extra=f'[git]\nmode = "{mode}"\n')
    git(repo, "add", "bulbi.toml")
    git(repo, "commit", "-q", "-m", "spec")
    worktree = add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    yield Project(mode, repo, worktree, tmp_path)
    # Whatever is left is removed by the session fixture.
    with suppress(docker.errors.DockerException):
        _remove_box(client, repo)


@pytest.fixture(params=["guarded", "isolated"])
def project(request, docker_client, tmp_path: Path) -> Iterator[Project]:
    yield from _make_project(docker_client, tmp_path, request.param)


@pytest.fixture
def isolated(docker_client, tmp_path: Path) -> Iterator[Project]:
    yield from _make_project(docker_client, tmp_path, "isolated")


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


# ---- isolated mode only (spec §3.4) --------------------------------------------------------


def test_isolated_box_never_sees_host_config_hooks_or_refs(isolated):
    git_dir = isolated.repo / ".git"
    git(isolated.repo, "config", "bulbitest.canary", "host-config")
    hook = git_dir / "hooks" / "post-checkout"
    hook.write_text("#!/bin/sh\n")
    hook.chmod(0o755)
    git(isolated.repo, "update-ref", "refs/bulbitest/hidden", "HEAD")
    script = (
        f"! git config bulbitest.canary && test ! -e {hook} && "
        f"! git show-ref --verify -q refs/bulbitest/hidden && "
        f"test ! -e {git_dir}/logs && git log -1 --format=%s main"
    )
    result = isolated.in_box(script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip().endswith("spec"), "history is read through the alternates"


def test_isolated_box_cannot_write_host_objects(isolated):
    result = isolated.in_box("touch /bulbi/host-objects/planted")
    assert result.returncode != 0 and "Read-only" in result.stdout + result.stderr
    assert not (isolated.repo / ".git" / "objects" / "planted").exists()


def _large_history(repo: Path) -> None:
    for index in range(40):
        (repo / f"blob{index}.bin").write_bytes(os.urandom(256 * 1024))
        git(repo, "add", f"blob{index}.bin")
        git(repo, "commit", "-q", "-m", f"blob {index}")


@pytest.fixture
def large(docker_client, tmp_path: Path) -> Iterator[Project]:
    yield from _make_project(docker_client, tmp_path, "isolated", _large_history)


def test_isolated_box_repo_stays_small_whatever_the_history(large):
    host_kib = int(subprocess.run(
        ["du", "-sk", str(large.repo / ".git" / "objects")], capture_output=True, text=True,
        check=True,
    ).stdout.split()[0])  # fmt: skip
    result = large.in_box(
        f"git log --oneline | wc -l && du -sk --exclude=index {large.repo}/.git | cut -f1"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    commits, box_kib = (int(line) for line in result.stdout.split()[-2:])
    assert commits >= 40 and host_kib > 9000
    assert box_kib < 1024, f"box repo uses {box_kib} KiB for a {host_kib} KiB history"


def _doomed_branch(repo: Path) -> None:
    """A host branch with a commit only it reaches; the box repo will rely on it."""
    git(repo, "checkout", "-q", "-b", "doomed")
    git(repo, "commit", "-q", "--allow-empty", "-m", "doomed")
    git(repo, "checkout", "-q", "main")


@pytest.fixture
def doomed(docker_client, tmp_path: Path) -> Iterator[Project]:
    yield from _make_project(docker_client, tmp_path, "isolated", _doomed_branch)


def test_pruned_host_history_is_refused_then_rebuilt_by_restart(doomed):
    first = doomed.in_box("git log -1 --format=%s doomed")
    assert first.returncode == 0 and "doomed" in first.stdout, first.stdout + first.stderr
    git(doomed.repo, "branch", "-q", "-D", "doomed")
    git(doomed.repo, "reflog", "expire", "--expire=now", "--all")
    git(doomed.repo, "gc", "-q", "--prune=now")

    refused = doomed.in_box("true")
    assert refused.returncode == 1
    assert "host history changed under the box" in refused.stdout + refused.stderr

    restart = bulbi(doomed.repo, "restart", "--yes")
    assert restart.returncode == 0, restart.stdout + restart.stderr
    rebuilt = doomed.in_box(f"git status --short && ls -a {doomed.repo}/.git")
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    assert ".bulbi-broken-" in rebuilt.stdout, "the broken repo is kept, not deleted"
