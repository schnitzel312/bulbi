"""``bulbi git-scan``: look for git metadata that would run code on this machine."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.commands.sandbox import profile_option
from bulbi.cli.context import AppContext
from bulbi.cli.render.git_safety import GitReportRenderer
from bulbi.sandbox.orchestrator import file_lock


class GitScanCommand(BulbiCommand):
    name = "git-scan"
    help = (
        "Scan the project's checkouts for git metadata the box planted that would run code "
        "on this machine, and apply [git] on_finding (exit 1 if anything is left in place)."
    )

    def parameters(self) -> Sequence[ClickDecorator]:
        return (profile_option,)

    def execute(self, app: AppContext, profile: str | None) -> None:
        guard = app.git_guard(app.load_spec(profile), profile)
        with file_lock(app.state_dir).hold():
            report = guard.scan()
        if report is None:
            app.console.print(
                "[dim]No git baseline yet: no box has been created for this project.[/dim]"
            )
            return
        GitReportRenderer(app.console).render(report, show_clean=True)
        if report.blocks_attach:
            click.get_current_context().exit(1)
