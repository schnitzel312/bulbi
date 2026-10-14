"""``bulbi restart``: rebuild the project's box from the current spec."""

from __future__ import annotations

from collections.abc import Sequence

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.commands.sandbox import confirm_ending_sessions, profile_option, yes_option
from bulbi.cli.context import AppContext
from bulbi.cli.render.progress import ConsoleSandboxObserver


class RestartCommand(BulbiCommand):
    name = "restart"
    help = "Recreate this project's box and gateway with the current spec."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (profile_option, yes_option)

    def execute(self, app: AppContext, profile: str | None, yes: bool) -> None:
        observer = ConsoleSandboxObserver(app.console)
        orchestrator = app.orchestrator(app.load_spec(profile), profile, observer)
        confirm_ending_sessions(orchestrator.active_sessions(), yes)
        orchestrator.recreate()
        app.console.print(f"[green]Restarted {orchestrator.identity.name}[/green]")
