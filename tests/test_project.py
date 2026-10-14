"""Tests for project discovery: one project per repository, whatever the worktree (§8.1, §9)."""

from pathlib import Path

from bulbi.project import Project, ProjectLocator, SubprocessGit
from tests.repos import add_worktree, make_repo


def test_project_key_is_the_same_from_main_checkout_and_every_worktree(tmp_path: Path):
    repo = make_repo(tmp_path / "app")
    a = add_worktree(repo, tmp_path / "trees" / "a", "a")
    b = add_worktree(repo, tmp_path / "elsewhere" / "b", "b")
    projects = [ProjectLocator().locate(path) for path in (repo, a, b, a / ".")]
    assert {p.key for p in projects} == {repo / ".git"}
    assert {p.root for p in projects} == {repo}
    assert [p.current for p in projects] == [repo, a, b, a]
    assert projects[1].worktrees[0] == repo  # main checkout first
    assert set(projects[1].linked_worktrees) == {a, b}


def test_cwd_inside_a_checkout_is_kept_for_the_session(tmp_path: Path):
    repo = make_repo(tmp_path / "app")
    (repo / "src").mkdir()
    project = ProjectLocator().locate(repo / "src")
    assert (project.current, project.cwd) == (repo, repo / "src")


def test_outside_git_the_project_is_the_directory(tmp_path: Path):
    project = ProjectLocator().locate(tmp_path)
    assert project == Project.plain(tmp_path)
    assert not project.is_git and project.worktrees == ()


def test_admin_dir_of_a_worktree(tmp_path: Path):
    repo = make_repo(tmp_path / "app")
    wt = add_worktree(repo, tmp_path / "trees" / "wt", "wt")
    project = ProjectLocator().locate(wt)
    assert project.admin_dir(wt) == repo / ".git" / "worktrees" / "wt"
    assert project.admin_dir(repo) is None


def test_git_client_tolerates_missing_git_binary(tmp_path: Path):
    def no_git(*args, **kwargs):
        raise FileNotFoundError("git")

    git = SubprocessGit(runner=no_git)
    assert git.common_dir(tmp_path) is None and git.worktrees(tmp_path) == []
    assert ProjectLocator(git).locate(tmp_path) == Project.plain(tmp_path)
