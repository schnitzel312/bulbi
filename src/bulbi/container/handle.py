"""The Docker implementation of :class:`~bulbi.agents.ports.ContainerHandle`."""

from __future__ import annotations

import io
import posixpath
import tarfile
import time
from collections.abc import Callable, Sequence
from functools import cached_property
from pathlib import PurePosixPath
from typing import Any

from bulbi.agents.ports import DEFAULT_FILE_MODE, ContainerHandle, ExecResult
from bulbi.constants import CONTAINER_HOME, CONTAINER_USER
from bulbi.container.docker_sdk import docker_errors
from bulbi.errors import SandboxError

Clock = Callable[[], float]


class DockerContainerHandle(ContainerHandle):
    """Runs commands with ``exec_run`` and writes files with ``put_archive``.

    Files travel as a tar stream rather than through a shell command, so their size is
    not limited by the kernel's argument limits and their content (e.g. OAuth tokens)
    never appears in a process's arguments. The Docker daemon extracts archives as root,
    so writes are confined to the sandbox user's home here, and each file is owned by
    that user.
    """

    def __init__(
        self,
        container: Any,
        user: str = CONTAINER_USER,
        home: str = CONTAINER_HOME,
        clock: Clock = time.time,
    ) -> None:
        self._container = container
        self._user = user
        self._home = PurePosixPath(home)
        self._clock = clock

    def exec(self, argv: Sequence[str]) -> ExecResult:
        with docker_errors(f"failed to run {argv[0]} in container"):
            result = self._container.exec_run(list(argv), user=self._user)
        output = result.output.decode() if result.output else ""
        return ExecResult(exit_code=result.exit_code, output=output)

    def write_file(self, path: str, content: str, *, mode: int = DEFAULT_FILE_MODE) -> None:
        target = self._inside_home(path)
        self._require(self.exec(["mkdir", "-p", str(target.parent)]), f"create {target.parent}")
        archive = self._single_file_archive(target.name, content.encode(), mode)
        with docker_errors(f"failed to write {path} in container"):
            written = self._container.put_archive(str(target.parent), archive)
        if not written:
            raise SandboxError(f"failed to write {path} in container")

    def _inside_home(self, path: str) -> PurePosixPath:
        """``path`` normalised, provided it is a file strictly inside the home directory."""
        target = PurePosixPath(posixpath.normpath(path))
        if not target.is_absolute() or self._home not in target.parents:
            raise SandboxError(f"refusing to write {path}: outside {self._home}")
        return target

    @cached_property
    def _owner_ids(self) -> tuple[int, int]:
        """Numeric uid and gid of the sandbox user (tar headers carry numbers)."""
        ids = [
            self._require(self.exec(["id", flag]), "look up sandbox user") for flag in ("-u", "-g")
        ]
        return int(ids[0]), int(ids[1])

    def _single_file_archive(self, name: str, data: bytes, mode: int) -> bytes:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        info.mtime = int(self._clock())
        info.uid, info.gid = self._owner_ids
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    @staticmethod
    def _require(result: ExecResult, action: str) -> str:
        if not result.succeeded:
            raise SandboxError(f"failed to {action} in container: {result.output.strip()}")
        return result.output.strip()
