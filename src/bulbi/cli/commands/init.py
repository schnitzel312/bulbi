"""``bulbi init``: write a starter spec for the current project."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext
from bulbi.constants import DEFAULT_AGENT, SPEC_FILENAME
from bulbi.detection import StarterSpecRenderer
from bulbi.errors import SpecError


class InitCommand(BulbiCommand):
    name = "init"
    help = "Generate a starter bulbi.toml for this project."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (click.option("--force", is_flag=True, help="Overwrite an existing bulbi.toml."),)

    def execute(self, app: AppContext, force: bool) -> None:
        spec_path = app.project_root / SPEC_FILENAME
        if spec_path.exists() and not force:
            raise SpecError(f"{SPEC_FILENAME} already exists. Use --force to overwrite.")
        project = app.detectors.detect(app.project_root)
        renderer = StarterSpecRenderer(app.agents.resolve(DEFAULT_AGENT))
        spec_path.write_text(renderer.render(project))
        app.console.print(f"[green]Wrote {SPEC_FILENAME}[/green]")
