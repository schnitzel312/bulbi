"""Shared behaviour of the commands that run something inside the sandbox."""

from __future__ import annotations

from collections.abc import Sequence
from typing import NoReturn

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext
from bulbi.cli.render.progress import ConsoleSandboxObserver
from bulbi.cli.render.validation import ValidationRenderer
from bulbi.constants import SPEC_FILENAME
from bulbi.sandbox import SandboxSession
from bulbi.spec import BulbiSpec

profile_option = click.option(
    "-p",
    "--profile",
    default=None,
    help="Apply a named profile from the spec.",
)
yes_option = click.option("--yes", is_flag=True, help="Do not ask for confirmation.")


def confirm_ending_sessions(sessions: int, yes: bool) -> None:
    """Ask before ending live sessions, unless ``--yes`` was given."""
    if sessions and not yes:
        click.confirm(
            f"{sessions} active session(s) will be ended. Continue?", abort=True, default=False
        )


class SandboxCommand(BulbiCommand):
    """Base for commands that run one command in the project's box and exit with its code."""

    def parameters(self) -> Sequence[ClickDecorator]:
        return (profile_option,)

    @staticmethod
    def run_in_sandbox(
        app: AppContext,
        spec: BulbiSpec,
        command: Sequence[str],
        label: str,
        profile: str | None = None,
    ) -> NoReturn:
        """Validate, attach to (or start) the box, run ``command``; exit with its exit code.

        The effective (profile-resolved) spec gets the same validation as ``check``:
        errors stop everything before any image is built; warnings are only shown.
        """
        result = app.validator.validate(spec)
        ValidationRenderer(app.console).render(result, show_success=False)
        if not result.ok:
            click.get_current_context().exit(1)
        if app.worktree_spec_differs():
            app.console.print(
                f"[yellow]! This worktree's {SPEC_FILENAME} differs from the main checkout's; "
                f"the box uses {app.project.root / SPEC_FILENAME}.[/yellow]"
            )
        observer = ConsoleSandboxObserver(app.console)
        services = app.sandbox_services()
        orchestrator = app.orchestrator(spec, profile, observer, services)
        with SandboxSession(orchestrator, services, observer) as session:
            exit_code = session.run(command, label)
        click.get_current_context().exit(exit_code)
