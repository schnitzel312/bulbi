"""``bulbi reset``: remove every Bulbi container and image."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext


class ResetCommand(BulbiCommand):
    name = "reset"
    help = "Remove all bulbi containers and images."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (
            click.confirmation_option(
                prompt="This will remove ALL bulbi containers and images. Continue?"
            ),
        )

    def execute(self, app: AppContext) -> None:
        app.box_manager().reset()
        app.console.print("[green]All bulbi containers and images removed.[/green]")
