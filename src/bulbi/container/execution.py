"""Running non-interactive commands inside a started container."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from bulbi.constants import CONTAINER_USER


@dataclass(frozen=True)
class ExecResult:
    """Outcome of a command run inside a container."""

    exit_code: int
    output: str

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class ContainerExecutor(ABC):
    """Runs a command inside one specific container and captures its output."""

    @abstractmethod
    def exec(self, argv: Sequence[str]) -> ExecResult:
        """Run ``argv`` as the sandbox user and wait for it to finish."""


class DockerContainerExecutor(ContainerExecutor):
    """Executes commands through the Docker SDK's ``exec_run``."""

    def __init__(self, container: Any, user: str = CONTAINER_USER) -> None:
        self._container = container
        self._user = user

    def exec(self, argv: Sequence[str]) -> ExecResult:
        result = self._container.exec_run(list(argv), user=self._user)
        output = result.output.decode() if result.output else ""
        return ExecResult(exit_code=result.exit_code, output=output)
