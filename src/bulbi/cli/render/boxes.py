"""Rendering Bulbi boxes for ``bulbi ls``."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from bulbi.cli.render.styles import ALLOWED_STYLE, CAUTION_STYLE, styled

RUNNING_STATUS = "running"
NOT_AVAILABLE = "-"


@dataclass(frozen=True)
class BoxRow:
    """One line of ``bulbi ls``."""

    name: str
    project: str
    profile: str
    status: str
    sessions: int
    uptime: str = NOT_AVAILABLE
    # TODO(bulbi): idle time needs the watcher to publish when sessions last ended.
    idle: str = NOT_AVAILABLE


class BoxTableRenderer:
    """Prints the box list, or a hint when there is none."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, rows: list[BoxRow]) -> None:
        if not rows:
            self._console.print("[dim]No running bulbi containers.[/dim]")
            return
        table = Table(title="Bulbi Boxes")
        table.add_column("Box", style="cyan")
        table.add_column("Project")
        table.add_column("Profile")
        table.add_column("State")
        table.add_column("Sessions", justify="right")
        table.add_column("Uptime")
        table.add_column("Idle")
        for row in rows:
            style = ALLOWED_STYLE if row.status == RUNNING_STATUS else CAUTION_STYLE
            table.add_row(
                row.name,
                row.project,
                row.profile or NOT_AVAILABLE,
                styled(row.status, style),
                str(row.sessions),
                row.uptime,
                row.idle,
            )
        self._console.print(table)
