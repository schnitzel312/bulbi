"""Tests for git safety (docs/specs/git-safety.md §5, unit part) with real temporary repos.

The "marker" tests reproduce the review's attack: an fsmonitor hook that touches a file
when the *host* runs ``git status``. They fail without the scan's neutralisation.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from bulbi.agents import ContainerHandle, ExecResult
from bulbi.constants import CONTAINER_HOME
from bulbi.container.execstream import BoxStream
from bulbi.container.gitvolume import GitVolumeManager
from bulbi.container.identity import BoxIdentity
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
from bulbi.gitsafety.isolated import (
    BROKEN_PREFIX,
    HOST_OBJECTS_MOUNT,
    BoxRepo,
    BundlePuller,
    CheckoutSlot,
    HostRefsExporter,
    HostRepoState,
    safe_config,
)
from bulbi.gitsafety.modes import IsolatedGitMode
from bulbi.gitsafety.quarantine import QUARANTINE_DIR
from bulbi.project import Project, ProjectLocator
from bulbi.spec import BoxSpec, BulbiSpec, FindingPolicy, GitSpec, MountSpec, ToolsSpec
from tests.fakes import FakeContainerHandle
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


def test_bare_repository_shaped_directory_is_quarantined(repo, tmp_path):
    """git treats a directory with HEAD, objects/ and refs/ as a repository when run
    inside it, so an agent need not even name it .git."""
    guard = _start_box(_project(repo))
    marker = tmp_path / "PWNED"
    bare = repo / "assets"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    git(bare, "config", "core.bare", "false")
    git(bare, "config", "core.worktree", str(repo))
    git(bare, "config", "core.fsmonitor", str(_hook_script(tmp_path, marker)))
    assert _reasons(guard.scan()) == [("new_git_dir", bare)]
    (repo / "assets").mkdir()
    _host_git_status(repo / "assets")
    assert not marker.exists()


def test_existing_bare_repositories_are_part_of_the_baseline(repo):
    subprocess.run(["git", "init", "-q", "--bare", str(repo / "fixtures.git")], check=True)
    assert _start_box(_project(repo)).scan().clean


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


def test_the_baseline_is_complete_whatever_the_budget(repo):
    """An incomplete baseline would make every later scan flag what it missed."""
    nested = make_repo(repo / "vendor" / "lib")
    ticks = iter(range(0, 10_000, 5))
    guard = _start_box(_project(repo), GitSpec(scan_budget="1s"), clock=lambda: next(ticks))
    baseline = BaselineStore(baseline_path(repo / ".bulbi")).load()
    assert nested / ".git" in baseline.snapshot.entries
    assert not guard.scan().complete


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


# ---- isolated mode (spec §3): the box repo, built and checked with real git ------------
#
# LocalBox runs the box-side commands on this machine. The "box view" of a project is a
# checkout whose .git is an empty directory (the volume); the host repository is separate
# and reached only through alternates, as in the box.


class LocalBox(ContainerHandle):
    """A ContainerHandle running locally, with the box's fixed paths translated."""

    def __init__(self, home: Path, host_objects: Path) -> None:
        self.paths = {CONTAINER_HOME: str(home), HOST_OBJECTS_MOUNT: str(host_objects)}
        self.root_commands: list[list[str]] = []

    def _local(self, text: str) -> str:
        for box_path, local in self.paths.items():
            text = text.replace(box_path, local)
        return text

    def exec(self, argv, *, as_root=False):
        if as_root:
            self.root_commands.append(list(argv))
        result = subprocess.run(
            [self._local(arg) for arg in argv], capture_output=True, text=True, check=False
        )
        return ExecResult(result.returncode, result.stdout + result.stderr)

    def write_file(self, path, content, *, mode=0o644):
        target = Path(self._local(path))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self._local(content))


class LocalStream(BoxStream):
    """BoxStream running locally (the fake runner for bundle pulls)."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv, sink):
        self.calls.append(list(argv))
        result = subprocess.run(list(argv), capture_output=True, check=False)
        sink.write(result.stdout)
        return ExecResult(result.returncode, result.stderr.decode())


@dataclass
class Isolated:
    host: Project
    view: Project
    box: LocalBox

    @property
    def repo(self) -> BoxRepo:
        return BoxRepo(self.box, self.view)

    def box_git(self, *args: str) -> str:
        return git(self.view.root, *args)


@pytest.fixture
def isolated(tmp_path, repo) -> Isolated:
    git(repo, "tag", "-a", "v1", "-m", "release")
    git(repo, "branch", "side")
    add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    view_root = tmp_path / "box" / "app"
    subprocess.run(["git", "clone", "-q", str(repo), str(view_root)], check=True)
    shutil.rmtree(view_root / ".git")
    (view_root / ".git").mkdir()
    view = Project(view_root, view_root, view_root, view_root, (view_root,), view_root / ".git")
    box = LocalBox(tmp_path / "home", repo / ".git" / "objects")
    return Isolated(_project(repo), view, box)


def _host_state(isolated: Isolated):
    state = HostRefsExporter().export(isolated.host)
    return replace(state, slots=())  # the box view has no linked worktrees


def test_safe_config_runs_nothing_and_never_gcs(tmp_path):
    config = tmp_path / "config"
    for object_format in ("sha1", "sha256"):
        config.write_text(safe_config(object_format))
        entries = HostGitConfigReader().read(config)
        registry = ExecConfigRegistry.builtin()
        assert not [e for e in entries if registry.is_exec(e.key, e.value)]
        assert ConfigEntry("gc.auto", "0") in entries
    assert ConfigEntry("extensions.objectformat", "sha256") in entries


def test_refs_export_reads_refs_heads_and_tags_but_never_config(isolated):
    git(isolated.host.root, "config", "remote.origin.url", "https://token@example.com/x")
    state = HostRefsExporter().export(isolated.host)
    names = {ref.name for ref in state.refs}
    assert names == {"refs/heads/main", "refs/heads/side", "refs/heads/wt", "refs/tags/v1"}
    tag = next(ref for ref in state.refs if ref.name == "refs/tags/v1")
    assert tag.peeled == git(isolated.host.root, "rev-parse", "v1^{commit}")
    assert state.head == "ref: refs/heads/main" and state.object_format == "sha1"
    assert [(slot.name, slot.head) for slot in state.slots] == [("wt", "ref: refs/heads/wt")]
    assert "token" not in state.packed_refs()
    assert state.packed_refs().startswith("# pack-refs with: peeled fully-peeled sorted")


def test_box_repo_shares_history_through_read_only_alternates(isolated):
    host_refs = git(isolated.host.root, "for-each-ref")
    isolated.repo.build(_host_state(isolated))

    git_dir = isolated.view.root / ".git"
    alternates = (git_dir / "objects" / "info" / "alternates").read_text()
    assert alternates == f"{isolated.host.git_dir / 'objects'}\n"
    assert isolated.box_git("log", "--format=%s", "side") == "initial"
    assert isolated.box_git("for-each-ref") == host_refs
    assert isolated.box_git("status", "--porcelain") == ""
    assert isolated.box_git("config", "gc.auto") == "0"
    copied = [p for p in (git_dir / "objects").rglob("*") if p.is_file() and "info" not in p.parts]
    assert copied == [], "no history is copied into the box repo"
    assert git(isolated.host.root, "for-each-ref") == host_refs


def test_box_repo_gives_linked_worktrees_their_admin_dir(isolated, tmp_path):
    isolated.repo.build(_host_state(isolated))
    checkout = tmp_path / "box" / "wt"
    subprocess.run(
        ["git", "clone", "-q", "-b", "wt", str(isolated.host.root), str(checkout)], check=True
    )
    shutil.rmtree(checkout / ".git")
    (checkout / ".git").write_text(f"gitdir: {isolated.view.git_dir}/worktrees/wt\n")
    isolated.repo.add_checkout(CheckoutSlot("wt", checkout, "ref: refs/heads/wt"))
    assert git(checkout, "status", "--porcelain", "--branch") == "## wt"
    assert isolated.repo.has_checkout("wt")


def test_fresh_volume_is_opened_to_the_box_user_by_root(isolated):
    isolated.view.git_dir.chmod(0o555)
    try:
        isolated.repo.build(_host_state(isolated))
    finally:
        isolated.view.git_dir.chmod(0o755)
    assert isolated.box.root_commands == [["chmod", "0777", str(isolated.view.git_dir)]]


def test_refresh_adds_host_branches_and_never_overwrites_the_box_s(isolated):
    isolated.repo.build(_host_state(isolated))
    git(isolated.view.root, "commit", "-q", "--allow-empty", "-m", "agent work")
    git(isolated.host.root, "branch", "later")
    git(isolated.host.root, "commit", "-q", "--allow-empty", "-m", "user work")
    isolated.repo.refresh(_host_state(isolated))
    assert isolated.box_git("log", "-1", "--format=%s", "main") == "agent work"
    assert isolated.box_git("rev-parse", "later") == git(isolated.host.root, "rev-parse", "later")


def test_pruned_host_history_is_detected_then_set_aside_and_rebuilt(isolated):
    isolated.repo.build(_host_state(isolated))
    assert isolated.repo.healthy()
    git(isolated.host.root, "checkout", "-q", "-b", "doomed")
    git(isolated.host.root, "commit", "-q", "--allow-empty", "-m", "doomed")
    isolated.repo.refresh(_host_state(isolated))  # the box now relies on "doomed"
    git(isolated.host.root, "checkout", "-q", "main")
    git(isolated.host.root, "branch", "-q", "-D", "doomed")
    git(isolated.host.root, "reflog", "expire", "--expire=now", "--all")
    git(isolated.host.root, "gc", "-q", "--prune=now")
    assert not isolated.repo.healthy()

    aside = isolated.repo.set_aside()
    isolated.repo.build(_host_state(isolated))
    assert isolated.repo.healthy()
    assert (Path(aside) / "packed-refs").is_file(), "the broken repo is kept"


def test_bundle_pull_fetches_the_box_s_commits_into_the_bulbi_namespace(isolated):
    isolated.repo.build(_host_state(isolated))
    (isolated.view.root / "agent.txt").write_text("done\n")
    git(isolated.view.root, "add", "agent.txt")
    git(isolated.view.root, "commit", "-q", "-m", "agent work")
    stream = LocalStream()
    puller = BundlePuller(stream, isolated.host, box_git_dir=str(isolated.view.git_dir))

    result = puller.pull("main")

    assert result.refs == ("refs/remotes/bulbi/main",)
    assert git(isolated.host.root, "log", "-1", "--format=%s", "bulbi/main") == "agent work"
    assert git(isolated.host.root, "log", "-1", "--format=%s", "main") == "initial"
    bundle_call = next(call for call in stream.calls if "bundle" in call)
    assert "--not" in bundle_call, "only objects missing from the host travel"


def test_bundle_pull_with_nothing_new_just_records_the_tips(isolated):
    isolated.repo.build(_host_state(isolated))
    stream = LocalStream()
    result = BundlePuller(stream, isolated.host, box_git_dir=str(isolated.view.git_dir)).pull()
    assert "refs/remotes/bulbi/side" in result.refs
    assert not any("bundle" in call for call in stream.calls)
    assert git(isolated.host.root, "rev-parse", "bulbi/side") == git(
        isolated.host.root, "rev-parse", "side"
    )


def test_bundle_pull_of_an_unknown_branch_is_an_error(isolated):
    isolated.repo.build(_host_state(isolated))
    puller = BundlePuller(LocalStream(), isolated.host, box_git_dir=str(isolated.view.git_dir))
    with pytest.raises(GitSafetyError, match="no branch 'nope'"):
        puller.pull("nope")


class _BrokenBox(FakeContainerHandle):
    """A box repo that exists but whose history the host pruned."""

    def exec(self, argv, *, as_root=False):
        super().exec(argv, as_root=as_root)
        return ExecResult(3 if "cat-file" in " ".join(argv) else 0, "")


class _FixedExporter(HostRefsExporter):
    def export(self, project):
        return HostRepoState("sha1", "ref: refs/heads/main", ())


def _isolated_mode(repo: Path) -> IsolatedGitMode:
    project = _project(repo)
    identity = BoxIdentity(project.key, "demo")
    return IsolatedGitMode(project, identity, GitVolumeManager(None), _FixedExporter())


def test_broken_history_refuses_attach_and_restart_of_a_stopped_box(repo):
    mode = _isolated_mode(repo)
    with pytest.raises(GitSafetyError, match="bulbi pull"):
        mode.attach(_BrokenBox())
    with pytest.raises(GitSafetyError, match="bulbi restart"):
        mode.prepare_box(_BrokenBox(), created=False)


def test_a_new_box_sets_a_broken_repo_aside_and_rebuilds(repo):
    box = _BrokenBox()
    _isolated_mode(repo).prepare_box(box, created=True)
    scripts = [" ".join(command) for command in box.commands]
    assert any(BROKEN_PREFIX in script and "find" in script for script in scripts)
    assert any("git init -q --bare" in script for script in scripts)


def test_host_git_is_hermetic(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 0, "", "")

    HostGit(runner, environment={"GIT_CONFIG_GLOBAL": "/home/me/.gitconfig"}).run(["status"])
    env = calls[0]["env"]
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert calls[0]["cwd"] == Path("/")
