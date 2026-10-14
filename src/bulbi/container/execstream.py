"""Streaming a command's binary stdout out of a box (``docker exec``), e.g. a git bundle.

``exec_run`` decodes and buffers everything; this writes stdout to a sink as it arrives
and keeps stderr apart, so binary output of any size reaches the host intact.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any, BinaryIO

from bulbi.agents.ports import ExecResult
from bulbi.constants import CONTAINER_USER
from bulbi.docker_sdk import docker_errors


class BoxStream(ABC):
    """Runs a command in the box, writing its stdout to ``sink``."""

    @abstractmethod
    def run(self, argv: Sequence[str], sink: BinaryIO) -> ExecResult:
        """Return the exit code and stderr (as ``output``)."""


class DockerExecStream(BoxStream):
    """``docker exec`` as the box user through the low-level API."""

    def __init__(self, docker_client: Any, container_id: str, user: str = CONTAINER_USER) -> None:
        self._api = docker_client.api
        self._container_id = container_id
        self._user = user

    def run(self, argv: Sequence[str], sink: BinaryIO) -> ExecResult:
        errors = bytearray()
        with docker_errors(f"failed to run {argv[0]} in container"):
            created = self._api.exec_create(
                self._container_id, list(argv), stdout=True, stderr=True, user=self._user
            )
            for stdout, stderr in self._api.exec_start(created["Id"], stream=True, demux=True):
                if stdout:
                    sink.write(stdout)
                if stderr:
                    errors.extend(stderr)
            exit_code = self._api.exec_inspect(created["Id"]).get("ExitCode")
        code = 1 if exit_code is None else int(exit_code)
        return ExecResult(code, errors.decode(errors="replace"))
