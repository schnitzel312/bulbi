"""Tests for git safety (docs/specs/git-safety.md §5, unit part) with real temporary repos.

The "marker" tests reproduce the review's attack: an fsmonitor hook that touches a file
when the *host* runs ``git status``. They fail without the scan's neutralisation.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from bulbi.container.mounts import MountPlanner, host_exposure
from bulbi.errors import GitSafetyError
from bulbi.gateway.audit import AuditLogReader, audit_log_path
from bulbi.gitsafety import (
    ExecConfigFinding,
    ExecConfigRegistry,
    ForeignPointerFinding,
    GitGuard,
    HookChangedFinding,
)
from bulbi.gitsafety.baseline import BaselineStore, GitBaseline, baseline_path
from bulbi.gitsafety.config import (
    COMMENT_PREFIX,
    ConfigEntry,
    GitConfigEditor,
    GitConfigReader,
    HostGitConfigReader,
    commented_out,
)
from bulbi.gitsafety.hostgit import HostGit
from bulbi.gitsafety.inventory import GitInventory
from bulbi.gitsafety.isolated import BoxClonePuller, BoxClones
from bulbi.gitsafety.quarantine import QUARANTINE_DIR
from bulbi.project import Project, ProjectLocator
from bulbi.spec import BoxSpec, BulbiSpec, FindingPolicy, GitSpec, MountSpec, ToolsSpec
from tests.repos import add_worktree, git, make_repo

SPEC = BulbiSpec(
    spec_version="0.1", box=BoxSpec(name="demo"), tools=ToolsSpec(), mounts=[MountSpec(".")]
)


# ---- fixtures and helpers --------------------------------------------------------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "code" / "app")


@pytest.fixture
def worktree(tmp_path: Path, repo: Path) -> Path:
    return add_worktree(repo, tmp_path / "trees" / "wt", "wt")


def _project(path: Path) -> Project:
    return ProjectLocator().locate(path)


def _guard(project: Project, settings: GitSpec | None = None, **kwargs) -> GitGuard:
    return GitGuard.for_project(
        settings or GitSpec(), project.root, project.root / ".bulbi", **kwargs
    )


def _start_box(project: Project, settings: GitSpec | None = None, *, overlays=True, **kwargs):
    """Record the baseline exactly as box creation does, from the planned mounts."""
    guard = _guard(project, settings, **kwargs)
    exposure = host_exposure(MountPlanner(project).plan(SPEC))
    protected = exposure.protected if overlays else ()
    guard.record_baseline(exposure.writable, protected, project.git_dir)
    return guard


def _hook_script(directory: Path, marker: Path) -> Path:
    script = directory / "pwn.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    script.chmod(0o755)
    return script


def _host_git_status(cwd: Path) -> None:
    subprocess.run(["git", "status"], cwd=cwd, capture_output=True, check=False)


def _plant_fsmonitor_repo(at: Path, marker: Path) -> Path:
    """Vector C: a nested repository whose config runs a hook on `git status`."""
    nested = make_repo(at)
    git(nested, "config", "core.fsmonitor", str(_hook_script(at.parent, marker)))
    return nested


def _reasons(report) -> list[tuple[str, Path]]:
    return [(f.reason.value, f.path) for f in report.findings]


# ---- the exec-key registry -------------------------------------------------------------

SPEC_SECTION_1_KEYS = [
    ("core.fsmonitor", "/x/hook"),
    ("core.hookspath", "hooks"),
    ("core.sshcommand", "ssh -i k"),
    ("core.pager", "less"),
    ("core.editor", "vim"),
    ("core.askpass", "/x"),
    ("credential.helper", "store"),
    ("credential.https://example.com.helper", "/x"),
    ("diff.external", "/x"),
    ("diff.png.textconv", "exif"),
    ("filter.lfs.clean", "x"),
    ("filter.lfs.smudge", "x"),
    ("filter.lfs.process", "x"),
    ("merge.ours.driver", "true"),
    ("gpg.program", "gpg2"),
    ("gpg.ssh.program", "ssh-keygen"),
    ("sequence.editor", "vim"),
    ("uploadpack.packobjectshook", "/x"),
    ("alias.st", "!sh -c 'id'"),
]


@pytest.mark.parametrize(("key", "value"), SPEC_SECTION_1_KEYS)
def test_registry_covers_every_key_in_spec_section_1(key, value):
    assert ExecConfigRegistry.builtin().is_exec(key, value)


@pytest.mark.parametrize(
    ("key", "value"),
    [("alias.st", "status"), ("core.fsmonitor", "true"), ("core.fsmonitor", "false"),
     ("core.autocrlf", "true"), ("user.email", "a@b"), ("submodule.x.update", "rebase")],
)  # fmt: skip
def test_registry_ignores_harmless_values(key, value):
    assert not ExecConfigRegistry.builtin().is_exec(key, value)


def test_registry_matches_keys_case_insensitively():
    registry = ExecConfigRegistry.builtin()
    assert registry.is_exec("core.hooksPath", "x")
    assert registry.is_exec("submodule.Lib.update", "!rm -rf /")


# ---- reading and editing config --------------------------------------------------------


def test_host_reader_lists_keys_as_git_prints_them(tmp_path):
    config = tmp_path / "config"
    config.write_text('[core]\n\tbare\n[Filter "Lfs"]\n\tClean = a\\\n b\n')
    entries = HostGitConfigReader().read(config)
    assert entries == (ConfigEntry("core.bare", None), ConfigEntry("filter.Lfs.clean", "a b"))


def test_host_reader_reports_unparseable_files(tmp_path):
    config = tmp_path / "config"
    config.write_text("[core\n")
    with pytest.raises(GitSafetyError):
        HostGitConfigReader().read(config)


def test_commented_out_handles_continuations_inline_keys_and_subsections():
    text = (
        "[core]\n\tpager = less \\\n  -R\n\teditor = vim\n"
        "[core] pager = more\n"
        '[pager "core"]\n\tpager = keep\n'
        "[core.sub]\n\tpager = keep-too\n"
    )
    result = commented_out(text, "core.pager")
    assert result == (
        f"[core]\n{COMMENT_PREFIX}\tpager = less \\\n{COMMENT_PREFIX}  -R\n\teditor = vim\n"
        f"[core]\n{COMMENT_PREFIX}pager = more\n"
        '[pager "core"]\n\tpager = keep\n'
        "[core.sub]\n\tpager = keep-too\n"
    )


def test_editor_keeps_trusted_values(tmp_path):
    config = tmp_path / "config"
    config.write_text("[credential]\n\thelper = osxkeychain\n\thelper = !evil\n")
    reader = HostGitConfigReader()
    GitConfigEditor(reader).neutralise(config, "credential.helper", ["osxkeychain"])
    assert reader.read(config) == (ConfigEntry("credential.helper", "osxkeychain"),)


class _StubbornReader(GitConfigReader):
    """Claims the key survives the line edit once (a line the editor cannot attribute)."""

    def __init__(self) -> None:
        self._real = HostGitConfigReader()
        self.calls = 0

    def read(self, path):
        self.calls += 1
        if self.calls == 1:
            return (ConfigEntry("core.pager", "evil"),)
        return self._real.read(path)


def test_editor_falls_back_to_git_unset_when_the_line_edit_misses(tmp_path):
    config = tmp_path / "config"
    config.write_text("[core]\n\tpager = evil\n")
    reader = _StubbornReader()
    GitConfigEditor(reader).neutralise(config, "core.pager")
    assert reader.calls == 2
    assert HostGitConfigReader().read(config) == ()


# ---- scans: vector C and new git dirs ---------------------------------------------------


def test_a_clean_box_has_no_findings(repo, worktree):
    guard = _start_box(_project(repo))
    report = guard.scan()
    assert report is not None and report.clean and not report.blocks_attach


def test_no_baseline_means_nothing_to_compare(repo):
    assert _guard(_project(repo)).scan() is None


def test_vector_c_nested_repo_is_quarantined_and_host_git_runs_nothing(repo, tmp_path):
    guard = _start_box(_project(repo))
    marker = tmp_path / "PWNED"
    nested = _plant_fsmonitor_repo(repo / "src", marker)

    report = guard.scan()

    assert _reasons(report) == [("new_git_dir", nested / ".git")]
    assert not (nested / ".git").exists()
    _host_git_status(nested)
    assert not marker.exists(), "host git executed agent-controlled code"
    stored = repo / ".bulbi" / QUARANTINE_DIR / report.record_id / "src" / ".git"
    assert (stored / "config").is_file()


def test_vector_c_marker_fires_without_the_scan(repo, tmp_path):
    """Control for the test above: the planted repo really runs code on the host."""
    _start_box(_project(repo))
    marker = tmp_path / "PWNED"
    nested = _plant_fsmonitor_repo(repo / "src", marker)
    _host_git_status(nested)
    assert marker.exists()


def test_vector_c_gitfile_pointing_at_an_agent_gitdir(repo, tmp_path):
    guard = _start_box(_project(repo))
    evil = make_repo(repo / "evil")  # itself a new repository
    (repo / "src").mkdir()
    (repo / "src" / ".git").write_text(f"gitdir: {evil / '.git'}\n")
    findings = {
        (f.reason.value, f.path, getattr(f, "target", None)) for f in guard.scan().findings
    }
    assert findings == {
        ("new_git_dir", evil / ".git", None),
        ("new_git_dir", repo / "src" / ".git", (evil / ".git").resolve()),
    }


def test_symlinked_git_entry_is_a_finding(repo, tmp_path):
    guard = _start_box(_project(repo))
    (repo / "src").mkdir()
    (repo / "src" / ".git").symlink_to(tmp_path)
    assert _reasons(guard.scan()) == [("new_git_dir", repo / "src" / ".git")]
    assert not (repo / "src" / ".git").is_symlink()


def test_worktree_added_in_the_box_is_legitimate(repo, worktree):
    guard = _start_box(_project(repo))
    add_worktree(repo, worktree.parent / "agent", "agent")
    assert guard.scan().clean


def test_late_worktree_with_a_repointed_commondir_is_quarantined_review(repo, worktree, tmp_path):
    """Review: a worktree created after start has writable pointer files until restart."""
    guard = _start_box(_project(repo))
    late = add_worktree(repo, worktree.parent / "late", "late")
    admin = repo / ".git" / "worktrees" / "late"
    evil = make_repo(tmp_path / "evil")
    (admin / "commondir").write_text(f"{evil / '.git'}\n")
    report = guard.scan()
    assert ("new_git_dir", admin) in _reasons(report)
    assert not admin.exists() and (late / ".git").is_file()


def test_late_worktree_with_a_repointed_git_file_is_quarantined(repo, worktree, tmp_path):
    guard = _start_box(_project(repo))
    late = add_worktree(repo, worktree.parent / "late", "late")
    marker = tmp_path / "PWNED"
    evil = _plant_fsmonitor_repo(tmp_path / "evil", marker)
    (late / ".git").write_text(f"gitdir: {evil / '.git'}\n")
    assert ("new_git_dir", late / ".git") in _reasons(guard.scan())
    _host_git_status(late)
    assert not marker.exists()


def test_skipped_directories_are_not_walked(repo, tmp_path):
    guard = _start_box(_project(repo))
    make_repo(repo / "node_modules" / "pkg")
    assert guard.scan().clean


# ---- scans: pointers --------------------------------------------------------------------


def test_baseline_git_file_repointed_outside_is_a_foreign_pointer(repo, worktree, tmp_path):
    guard = _start_box(_project(repo), overlays=False)
    (worktree / ".git").write_text(f"gitdir: {tmp_path / 'elsewhere'}\n")
    report = guard.scan()
    assert report.findings == (
        ForeignPointerFinding(worktree / ".git", (tmp_path / "elsewhere").resolve()),
    )


def test_baseline_commondir_repointed_moves_the_admin_dir(repo, worktree, tmp_path):
    guard = _start_box(_project(repo), overlays=False)
    admin = repo / ".git" / "worktrees" / "wt"
    (admin / "commondir").write_text(f"{tmp_path}\n")
    report = guard.scan()
    assert [type(f) for f in report.findings] == [ForeignPointerFinding]
    assert report.findings[0].subject == admin and not admin.exists()


def test_baseline_gitdir_repointed_is_a_foreign_pointer(repo, worktree, tmp_path):
    guard = _start_box(_project(repo), overlays=False)
    admin = repo / ".git" / "worktrees" / "wt"
    other = tmp_path / "other"
    other.mkdir()
    (other / ".git").write_text("gitdir: /nowhere\n")
    (admin / "gitdir").write_text(f"{other / '.git'}\n")
    assert _reasons(guard.scan()) == [("foreign_pointer", admin / "gitdir")]


def test_read_only_overlays_are_not_scanned(repo, worktree, tmp_path):
    """Files the box cannot write (overlays) change only by the user's own hand."""
    guard = _start_box(_project(repo))
    git(repo, "config", "core.pager", "less")
    (worktree / ".git").write_text(f"gitdir: {tmp_path}\n")
    assert guard.scan().clean


def test_submodule_style_pointer_into_modules_is_legitimate(repo):
    guard = _start_box(_project(repo))
    module = repo / ".git" / "modules" / "lib"
    module.mkdir(parents=True)
    (repo / "lib").mkdir()
    (repo / "lib" / ".git").write_text("gitdir: ../.git/modules/lib\n")
    assert guard.scan().clean


# ---- scans: exec config, includes, hooks ------------------------------------------------


def test_new_worktree_config_with_an_exec_key(repo, worktree):
    guard = _start_box(_project(repo))
    config = repo / ".git" / "worktrees" / "wt" / "config.worktree"
    config.write_text("[core]\n\tfsmonitor = /tmp/hook\n")
    report = guard.scan()
    assert report.findings == (ExecConfigFinding(config, "core.fsmonitor", ("/tmp/hook",)),)
    assert HostGitConfigReader().read(config) == ()
    backup = repo / ".bulbi" / QUARANTINE_DIR / report.record_id / ".git" / "worktrees" / "wt"
    assert "fsmonitor" in (backup / "config.worktree").read_text()


def test_existing_values_are_trusted_and_kept(repo):
    nested = make_repo(repo / "vendor" / "lib")
    git(nested, "config", "credential.helper", "osxkeychain")
    guard = _start_box(_project(repo))
    git(nested, "config", "--add", "credential.helper", "!evil")
    report = guard.scan()
    assert [f.detail for f in report.findings] == ["credential.helper"]
    assert git(nested, "config", "--local", "--get-all", "credential.helper") == "osxkeychain"


def test_includes_are_chased_recursively(repo):
    nested = make_repo(repo / "vendor" / "lib")
    guard = _start_box(_project(repo))
    first, second = repo / "first.cfg", repo / "second.cfg"
    first.write_text("[include]\n\tpath = second.cfg\n")
    second.write_text(f'[core]\n\tpager = evil\n[includeIf "gitdir:/x/"]\n\tpath = {first}\n')
    git(nested, "config", "include.path", str(first))
    report = guard.scan()
    assert _reasons(report) == [("git_exec_config", second)]


def test_changed_unparseable_config_is_moved(repo):
    nested = make_repo(repo / "vendor" / "lib")
    guard = _start_box(_project(repo))
    config = nested / ".git" / "config"
    config.write_text(config.read_text() + "[core\n")
    report = guard.scan()
    assert _reasons(report) == [("git_exec_config", config)]
    assert not config.exists()


def test_new_executable_hook_is_quarantined(repo, tmp_path):
    nested = make_repo(repo / "vendor" / "lib")
    guard = _start_box(_project(repo))
    hooks = nested / ".git" / "hooks"
    _hook_script(tmp_path, tmp_path / "x").rename(hooks / "pre-commit")
    (hooks / "notes.txt").write_text("not executable")
    report = guard.scan()
    assert report.findings == (HookChangedFinding(hooks / "pre-commit"),)
    assert not (hooks / "pre-commit").exists() and (hooks / "notes.txt").exists()


def test_hooks_path_directory_is_scanned(repo, tmp_path):
    nested = make_repo(repo / "vendor" / "lib")
    hooks = nested / ".githooks"
    hooks.mkdir()
    git(nested, "config", "core.hooksPath", ".githooks")
    guard = _start_box(_project(repo))
    _hook_script(tmp_path, tmp_path / "x").rename(hooks / "post-checkout")
    assert _reasons(guard.scan()) == [("hook_changed", hooks / "post-checkout")]


# ---- policies, budget, audit ------------------------------------------------------------


def test_block_mode_changes_nothing_and_blocks(repo, tmp_path):
    guard = _start_box(_project(repo), GitSpec(on_finding=FindingPolicy.BLOCK))
    nested = _plant_fsmonitor_repo(repo / "src", tmp_path / "PWNED")
    report = guard.scan()
    assert report.blocks_attach and report.record_id is None
    assert (nested / ".git").is_dir()
    assert not (repo / ".bulbi" / QUARANTINE_DIR).exists()
    assert "refusing to attach" in report.refusal()


def test_scan_budget_is_respected(repo):
    ticks = iter(range(0, 10_000, 5))
    guard = _start_box(_project(repo), GitSpec(scan_budget="10s"), clock=lambda: next(ticks))
    report = guard.scan()
    assert not report.complete and report.blocks_attach
    assert "scan_budget" in report.refusal()


def test_findings_are_audited(repo, tmp_path):
    guard = _start_box(_project(repo))
    nested = _plant_fsmonitor_repo(repo / "src", tmp_path / "PWNED")
    guard.scan()
    (entry,) = AuditLogReader(audit_log_path(repo)).entries()
    assert (entry.method, entry.reason, entry.action) == ("GIT", "new_git_dir", "quarantine")
    assert entry.domain == str(nested / ".git") and "moved to" in (entry.rule or "")


# ---- quarantine and restore ------------------------------------------------------------


def test_quarantine_and_restore_round_trip(repo, worktree, tmp_path):
    guard = _start_box(_project(repo))
    nested = _plant_fsmonitor_repo(repo / "src", tmp_path / "PWNED")
    config = repo / ".git" / "worktrees" / "wt" / "config.worktree"
    original = "[core]\n\tpager = evil\n[alias]\n\tst = !id\n\tco = checkout\n"
    config.write_text(original)
    report = guard.scan()
    assert len(report.findings) == 3

    guard.restore(report.record_id)

    assert config.read_text() == original
    assert git(nested, "config", "core.fsmonitor").endswith("pwn.sh")
    assert guard.scan().clean, "restored items are trusted from now on"
    with pytest.raises(GitSafetyError, match="already restored"):
        guard.restore(report.record_id)


def test_restore_never_overwrites(repo, tmp_path):
    guard = _start_box(_project(repo))
    nested = _plant_fsmonitor_repo(repo / "src", tmp_path / "PWNED")
    record_id = guard.scan().record_id
    (nested / ".git").mkdir()
    with pytest.raises(GitSafetyError, match="exists again"):
        guard.restore(record_id)


@pytest.mark.parametrize("bad", ["../../etc", "nope", "20260101T000000Z"])
def test_restore_rejects_unknown_ids(repo, bad):
    with pytest.raises(GitSafetyError):
        _guard(_project(repo)).restore(bad)


# ---- the baseline ----------------------------------------------------------------------


def test_baseline_round_trips_and_keeps_only_exec_entries(repo, worktree):
    nested = make_repo(repo / "vendor" / "lib")
    git(nested, "config", "core.pager", "less")
    _start_box(_project(repo))
    path = baseline_path(repo / ".bulbi")
    data = json.loads(path.read_text())
    kept = data["configs"][str(nested / ".git" / "config")]["exec_entries"]
    assert kept == [["core.pager", "less"]]
    baseline = BaselineStore(path).load()
    assert isinstance(baseline, GitBaseline) and baseline.common_dir == repo / ".git"
    assert repo in baseline.roots and worktree.parent in baseline.roots
    assert repo / ".git" / "config" in baseline.protected


def test_profiles_keep_their_own_baseline(repo):
    assert baseline_path(repo, "ro").name == "git-baseline-ro.json"
    assert baseline_path(repo).name == "git-baseline.json"


def test_corrupt_baseline_is_an_error(repo):
    path = baseline_path(repo / ".bulbi")
    path.parent.mkdir()
    path.write_text("{")
    with pytest.raises(GitSafetyError, match="bulbi restart"):
        _guard(_project(repo)).scan()


def test_inventory_does_not_descend_into_bulbi_state(repo):
    make_repo(repo / ".bulbi" / QUARANTINE_DIR / "x")
    snapshot = GitInventory(HostGitConfigReader()).take([repo], repo / ".git")
    assert list(snapshot.entries) == [repo / ".git"]


# ---- isolated mode: vetting and fetching a box clone ----------------------------------


@pytest.fixture
def box_clone(repo, tmp_path) -> Path:
    """What `bulbi pull` exports: a bare clone with a commit the agent made."""
    export = tmp_path / "export"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(export)], check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(export), str(work)], check=True)
    (work / "agent.txt").write_text("done\n")
    git(work, "add", "agent.txt")
    git(work, "commit", "-q", "-m", "agent work")
    git(work, "push", "-q", "origin", "main")
    return export


def _puller() -> BoxClonePuller:
    return BoxClonePuller(BoxClones(volumes=None))  # type: ignore[arg-type]


def test_pull_fetches_into_the_bulbi_namespace(repo, box_clone):
    result = _puller().fetch(box_clone, repo, "main")
    assert result.refs == ("bulbi/main",)
    assert git(repo, "log", "-1", "--format=%s", "bulbi/main") == "agent work"
    assert git(repo, "log", "-1", "--format=%s", "main") == "initial"


def test_pull_refuses_a_clone_whose_config_runs_code(repo, box_clone, tmp_path):
    marker = tmp_path / "PWNED"
    hook = _hook_script(tmp_path, marker)
    git(box_clone, "config", "uploadpack.packObjectsHook", str(hook))
    include = tmp_path / "inc.cfg"
    include.write_text(f"[core]\n\tsshCommand = {hook}\n")
    git(box_clone, "config", "include.path", str(include))
    with pytest.raises(GitSafetyError, match="refusing to pull") as raised:
        _puller().fetch(box_clone, repo)
    assert "uploadpack.packobjectshook" in str(raised.value)
    assert "core.sshcommand" in str(raised.value)
    assert not marker.exists()


@pytest.mark.parametrize("redirect", [".git", "commondir"])
def test_pull_refuses_a_clone_that_redirects_git(repo, box_clone, redirect):
    (box_clone / redirect).write_text("gitdir: /elsewhere\n")
    with pytest.raises(GitSafetyError, match="refusing to pull"):
        _puller().fetch(box_clone, repo)


def test_pull_rejects_bad_branch_names(repo, box_clone):
    with pytest.raises(GitSafetyError, match="not a valid branch"):
        _puller().fetch(box_clone, repo, "a..b")


def test_host_git_is_hermetic(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 0, "", "")

    HostGit(runner, environment={"GIT_CONFIG_GLOBAL": "/home/me/.gitconfig"}).run(["status"])
    env = calls[0]["env"]
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert calls[0]["cwd"] == Path("/")
