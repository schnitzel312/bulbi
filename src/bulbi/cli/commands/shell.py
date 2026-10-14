"""``bulbi shell``: an interactive shell in the sandbox."""

from __future__ import annotations

from bulbi.cli.commands.sandbox import SandboxCommand
from bulbi.cli.context import AppContext

SHELL_COMMAND = ("bash",)


class ShellCommand(SandboxCommand):
    name = "shell"
    help = "Open an interactive bash shell inside the sandbox."

    def execute(self, app: AppContext, profile: str | None) -> None:
        self.run_in_sandbox(app, app.load_spec(profile), SHELL_COMMAND, label="Opening shell")
