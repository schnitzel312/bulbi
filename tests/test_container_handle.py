"""Tests for the Docker-backed ContainerHandle (fake Docker SDK container)."""

import io
import tarfile

import docker.errors
import pytest

from bulbi.container.handle import DockerContainerHandle
from bulbi.errors import SandboxError
from tests.fakes import FakeContainer, FakeExecRun

ARG_MAX_PER_STRING = 128 * 1024


def _extract(archive: bytes) -> tuple[tarfile.TarInfo, bytes]:
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        (member,) = tar.getmembers()
        return member, tar.extractfile(member).read()


def test_write_file_streams_content_as_tar_owned_by_sandbox_user():
    container = FakeContainer("c")
    DockerContainerHandle(container).write_file("/home/bulbi/my dir/$x.json", "it's", mode=0o600)

    assert container.exec_calls[0] == (["mkdir", "-p", "/home/bulbi/my dir"], "bulbi")
    ((directory, archive),) = container.archives
    member, content = _extract(archive)
    assert directory == "/home/bulbi/my dir"
    temporary = ".$x.json.bulbi-tmp"
    assert (member.name, member.mode, member.uid, member.gid) == (temporary, 0o600, 1000, 1000)
    assert content == b"it's"
    # Atomic replace: readers never see a half-written file.
    assert container.exec_calls[-1] == (
        ["mv", "-f", f"/home/bulbi/my dir/{temporary}", "/home/bulbi/my dir/$x.json"],
        "bulbi",
    )


def test_large_files_never_go_through_process_arguments():
    """M1: ~/.claude.json can exceed the 128 KiB per-argument limit."""
    container = FakeContainer("c")
    content = "x" * (200 * 1024)
    DockerContainerHandle(container).write_file("/home/bulbi/.claude.json", content)

    assert all(len(arg) < ARG_MAX_PER_STRING for argv, _ in container.exec_calls for arg in argv)
    assert _extract(container.archives[0][1])[1] == content.encode()


def test_write_file_fails_when_parent_cannot_be_created():
    container = FakeContainer("c")
    container.exec_responses[("mkdir", "-p", "/home/bulbi/locked")] = FakeExecRun(
        1, b"Permission denied"
    )
    with pytest.raises(SandboxError, match="Permission denied"):
        DockerContainerHandle(container).write_file("/home/bulbi/locked/x", "y")


def test_write_file_fails_when_archive_is_rejected():
    container = FakeContainer("c")
    container.put_archive = lambda path, data: False  # type: ignore[method-assign]
    with pytest.raises(SandboxError, match="failed to write /home/bulbi/x"):
        DockerContainerHandle(container).write_file("/home/bulbi/x", "y")


def test_docker_errors_become_sandbox_errors():
    container = FakeContainer("c")

    def broken(argv, user):
        raise docker.errors.APIError("container is not running")

    container.exec_run = broken  # type: ignore[method-assign]
    with pytest.raises(SandboxError, match="container is not running"):
        DockerContainerHandle(container).exec(["true"])


def test_exec_runs_as_sandbox_user_and_decodes_output():
    container = FakeContainer("c")
    container.exec_responses[("claude", "--version")] = FakeExecRun(0, b"2.0.1\n")
    result = DockerContainerHandle(container).exec(["claude", "--version"])
    assert (result.exit_code, result.output) == (0, "2.0.1\n")
    assert container.exec_calls == [(["claude", "--version"], "bulbi")]


@pytest.mark.parametrize(
    "path",
    ["/etc/p2", "/home/bulbi/../../etc/p2", "relative/file", "/home/bulbi", "/home/bulbix/f"],
)
def test_write_file_is_restricted_to_the_container_home(path: str):
    """put_archive extracts as root, so the handle itself must keep writes inside $HOME."""
    container = FakeContainer("c")
    with pytest.raises(SandboxError, match="outside /home/bulbi"):
        DockerContainerHandle(container).write_file(path, "x")
    assert container.archives == []
    assert container.exec_calls == []


def test_written_files_carry_the_current_time():
    container = FakeContainer("c")
    DockerContainerHandle(container, clock=lambda: 1_700_000_000.9).write_file(
        "/home/bulbi/f", "x"
    )
    member, _ = _extract(container.archives[0][1])
    assert member.mtime == 1_700_000_000
