"""``bulbi rm``: remove one Bulbi container."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext


class RemoveCommand(BulbiCommand):
    name = "rm"
    help = "Remove a bulbi box (and its gateway) by name or ID."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (click.argument("container"),)

    def execute(self, app: AppContext, container: str) -> None:
        app.box_manager().remove_box(container)
        app.console.print(f"[green]Removed container: {container}[/green]")
