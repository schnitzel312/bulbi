"""Test doubles shared across test modules (no real Docker, keychain, or network)."""

from __future__ import annotations

import shlex
from collections.abc import Sequence

from bulbi.agents import CredentialProvider
from bulbi.container.execution import ContainerExecutor, ExecResult


class FakeExecutor(ContainerExecutor):
    """Records commands and simulates the files written through ``bash -c``."""

    def __init__(self, responses: dict[tuple[str, ...], ExecResult] | None = None) -> None:
        self.commands: list[list[str]] = []
        self._responses = responses or {}

    def exec(self, argv: Sequence[str]) -> ExecResult:
        self.commands.append(list(argv))
        return self._responses.get(tuple(argv), ExecResult(exit_code=0, output=""))

    @property
    def scripts(self) -> list[str]:
        return [cmd[2] for cmd in self.commands if cmd[:2] == ["bash", "-c"]]

    def written_files(self) -> dict[str, str]:
        """Map of path -> content for every ``echo CONTENT > PATH`` step."""
        files = {}
        for script in self.scripts:
            for step in script.split(" && "):
                tokens = shlex.split(step)
                if tokens[0] == "echo":
                    files[tokens[3]] = tokens[1]
        return files


class StaticCredentials(CredentialProvider):
    def __init__(self, value: str | None) -> None:
        self.value = value
        self.reads = 0

    def read(self) -> str | None:
        self.reads += 1
        return self.value
