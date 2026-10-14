"""Running the user's command interactively inside a box."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Sequence

from bulbi.constants import ENTRYPOINT_PATH

CommandRunner = Callable[[list[str]], "subprocess.CompletedProcess[bytes]"]


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

    def run(self, container_id: str, command: Sequence[str]) -> int:
        """Run ``command`` via the entrypoint (so setup runs first); return its exit code."""
        tty_flags = ["-it"] if self._is_terminal() else []
        argv = ["docker", "exec", *tty_flags, container_id, ENTRYPOINT_PATH, *command]
        return self._run(argv).returncode
