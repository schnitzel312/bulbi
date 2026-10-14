"""Writing files into a running container."""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from bulbi.container.execution import ContainerExecutor
from bulbi.errors import SandboxError


class ContainerFileWriter:
    """Creates files inside a container, creating parent directories as needed."""

    def __init__(self, executor: ContainerExecutor) -> None:
        self._executor = executor

    def write(self, path: str, content: str, *, mode: str | None = None) -> None:
        """Write ``content`` to ``path``; optionally ``chmod`` it to ``mode`` (e.g. ``"600"``)."""
        target = shlex.quote(path)
        steps = [
            f"mkdir -p {shlex.quote(str(PurePosixPath(path).parent))}",
            f"echo {shlex.quote(content)} > {target}",
        ]
        if mode:
            steps.append(f"chmod {shlex.quote(mode)} {target}")
        result = self._executor.exec(["bash", "-c", " && ".join(steps)])
        if not result.succeeded:
            raise SandboxError(f"failed to write {path} in container: {result.output.strip()}")
