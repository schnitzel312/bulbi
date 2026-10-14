"""Rendering Bulbi containers for ``bulbi ls``."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from bulbi.cli.render.styles import ALLOWED_STYLE, CAUTION_STYLE, styled
from bulbi.container.manager import BoxInfo

RUNNING_STATUS = "running"


class BoxTableRenderer:
    """Prints the container list, or a hint when there is none."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, boxes: list[BoxInfo]) -> None:
        if not boxes:
            self._console.print("[dim]No running bulbi containers.[/dim]")
            return
        table = Table(title="Bulbi Containers")
        table.add_column("ID", style="dim")
        table.add_column("Container", style="cyan")
        table.add_column("Box", style="bold")
        table.add_column("Status")
        for box in boxes:
            style = ALLOWED_STYLE if box.status == RUNNING_STATUS else CAUTION_STYLE
            table.add_row(box.id, box.name, box.box, styled(box.status, style))
        self._console.print(table)
