"""Tests for writing files into a container."""

import shlex

import pytest

from bulbi.container.execution import ExecResult
from bulbi.container.files import ContainerFileWriter
from bulbi.errors import SandboxError
from tests.fakes import FakeExecutor


def test_write_quotes_path_and_content():
    executor = FakeExecutor()
    ContainerFileWriter(executor).write("/home/bulbi/my dir/$x.json", "it's", mode="600")

    script = executor.scripts[0]
    assert shlex.split(script.split(" && ")[0]) == ["mkdir", "-p", "/home/bulbi/my dir"]
    assert executor.written_files() == {"/home/bulbi/my dir/$x.json": "it's"}
    assert script.endswith("chmod 600 '/home/bulbi/my dir/$x.json'")


def test_write_raises_when_command_fails():
    executor = FakeExecutor()
    executor.exec = lambda argv: ExecResult(1, "Permission denied")  # type: ignore[method-assign]
    with pytest.raises(SandboxError, match="Permission denied"):
        ContainerFileWriter(executor).write("/x", "y")
