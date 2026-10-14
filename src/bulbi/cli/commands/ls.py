"""``bulbi ls``: list Bulbi containers."""

from __future__ import annotations

from bulbi.cli.commands.base import BulbiCommand
from bulbi.cli.context import AppContext
from bulbi.cli.render.boxes import BoxTableRenderer


class ListCommand(BulbiCommand):
    name = "ls"
    help = "List all running bulbi containers."

    def execute(self, app: AppContext) -> None:
        BoxTableRenderer(app.console).render(app.box_manager().list_boxes())
