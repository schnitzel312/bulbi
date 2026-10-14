"""``bulbi run``: run the agent (or any command) in the sandbox."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import ClickDecorator
from bulbi.cli.commands.sandbox import SandboxCommand
from bulbi.cli.context import AppContext


class RunCommand(SandboxCommand):
    name = "run"
    help = "Build the sandbox and run a command (default: the configured agent)."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (*super().parameters(), click.argument("command", nargs=-1))

    def execute(self, app: AppContext, profile: str | None, command: tuple[str, ...]) -> None:
        spec = app.load_spec(profile)
        command = command or app.agent_for(spec).launch_command
        self.run_in_sandbox(app, spec, command, label="Running", profile=profile)
