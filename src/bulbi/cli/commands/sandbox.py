"""Shared behaviour of the commands that run something inside the sandbox."""

from __future__ import annotations

from collections.abc import Sequence
from typing import NoReturn

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext
from bulbi.cli.render.progress import ConsoleSandboxObserver
from bulbi.sandbox import SandboxSession
from bulbi.spec import BulbiSpec

profile_option = click.option(
    "-p",
    "--profile",
    default=None,
    help="Apply a named profile from the spec.",
)


class SandboxCommand(BulbiCommand):
    """Base for commands that bring up a box, run one command in it, and exit with its code."""

    def parameters(self) -> Sequence[ClickDecorator]:
        return (profile_option,)

    @staticmethod
    def run_in_sandbox(
        app: AppContext, spec: BulbiSpec, command: Sequence[str], label: str
    ) -> NoReturn:
        """Run ``command`` in a fresh box and exit the CLI with its exit code."""
        observer = ConsoleSandboxObserver(app.console)
        session = SandboxSession(
            spec, app.project_root, app.agent_for(spec), app.sandbox_services(), observer
        )
        with session:
            exit_code = session.run(command, label)
        click.get_current_context().exit(exit_code)
