"""The container entrypoint script, which runs the spec's setup commands once."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bulbi.constants import CONTAINER_HOME, CONTAINER_WORKSPACE

SETUP_MARKER_PATH = f"{CONTAINER_HOME}/.bulbi-setup-done"


@dataclass(frozen=True)
class EntrypointScript:
    """Runs ``setup_commands`` in the workspace on first start, then execs the command.

    Setup is deferred to container start because the project is bind-mounted at run time
    and so is not available while the image is built.
    """

    setup_commands: Sequence[str]

    def render(self) -> str:
        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# Run setup commands on first start (skip if already done).",
            f'MARKER="{SETUP_MARKER_PATH}"',
            'if [ ! -f "$MARKER" ]; then',
            f"    cd {CONTAINER_WORKSPACE}",
            *(f"    {command}" for command in self.setup_commands),
            '    touch "$MARKER"',
            "fi",
            "",
            "# Execute the requested command.",
            'exec "$@"',
            "",
        ]
        return "\n".join(lines)
