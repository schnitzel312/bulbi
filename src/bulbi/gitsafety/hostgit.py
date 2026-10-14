"""Running the host's ``git`` for the git-safety code, through an injected runner.

Every call is hermetic: it starts in a neutral directory (so no repository is
discovered) and ignores the user's system and global configuration, so a command
Bulbi runs on agent-controlled files cannot itself be steered into running code.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from bulbi.project.git import CommandRunner

NEUTRAL_DIRECTORY = Path("/")
_HERMETIC_ENVIRONMENT = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
}


class HostGit:
    """``git`` on the machine running Bulbi."""

    def __init__(
        self,
        runner: CommandRunner = subprocess.run,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._run = runner
        self._environment = dict(os.environ if environment is None else environment)

    def run(
        self, args: Sequence[str], cwd: Path = NEUTRAL_DIRECTORY
    ) -> subprocess.CompletedProcess[str]:
        """Run ``git args`` and return the finished process (never raises on failure)."""
        try:
            return self._run(
                ["git", *args],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                env={**self._environment, **_HERMETIC_ENVIRONMENT},
            )
        except OSError as exc:
            return subprocess.CompletedProcess(["git", *args], 127, "", str(exc))
