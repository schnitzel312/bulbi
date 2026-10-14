"""Running the user's command interactively inside a box."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence

from bulbi.constants import ENTRYPOINT_PATH

CommandRunner = Callable[..., "subprocess.CompletedProcess[bytes]"]


def _stdio_is_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


class TerminalExec:
    """Runs a command in a container through the ``docker exec`` CLI.

    The Docker CLI (rather than the SDK) handles TTY allocation, signal forwarding,
    and window resizing for interactive agents and shells.
    """

    def __init__(
        self,
        runner: CommandRunner = subprocess.run,
        is_terminal: Callable[[], bool] = _stdio_is_terminal,
    ) -> None:
        self._run = runner
        self._is_terminal = is_terminal

    def run(
        self,
        container_id: str,
        command: Sequence[str],
        workdir: str | None = None,
        environment: Mapping[str, str] | None = None,
        secret_environment: Mapping[str, str] | None = None,
    ) -> int:
        """Run ``command`` via the entrypoint (so setup runs first); return its exit code.

        Secret values are passed as ``-e NAME`` and handed to the Docker CLI through its
        own environment, so they never appear in any process's arguments.
        """
        options = ["-it"] if self._is_terminal() else []
        if workdir:
            options += ["-w", workdir]
        for key, value in (environment or {}).items():
            options += ["-e", f"{key}={value}"]
        for key in secret_environment or {}:
            options += ["-e", key]
        argv = ["docker", "exec", *options, container_id, ENTRYPOINT_PATH, *command]
        if not secret_environment:
            return self._run(argv).returncode
        return self._run(argv, env={**os.environ, **secret_environment}).returncode
