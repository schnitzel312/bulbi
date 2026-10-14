"""``bulbi git-restore``: put quarantined git metadata back."""

from __future__ import annotations

from collections.abc import Sequence

import click
from rich.markup import escape

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.commands.sandbox import profile_option
from bulbi.cli.context import AppContext
from bulbi.cli.render.git_safety import GitReportRenderer
from bulbi.sandbox.orchestrator import file_lock


class GitRestoreCommand(BulbiCommand):
    name = "git-restore"
    help = "Put a quarantine record back (without ID: list what is quarantined)."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (click.argument("record_id", required=False), profile_option)

    def execute(self, app: AppContext, record_id: str | None, profile: str | None) -> None:
        guard = app.git_guard(app.load_spec(profile), profile)
        if record_id is None:
            GitReportRenderer(app.console).render_records(guard.quarantine.records())
            return
        with file_lock(app.state_dir).hold():
            record = guard.restore(record_id)
        for item in record.items:
            app.console.print(f"[green]Restored[/green] {escape(str(item.original))}")
        app.console.print(
            "[yellow]Restored items are now trusted: git safety scans will not flag them "
            "again.[/yellow]"
        )
