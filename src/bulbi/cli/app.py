"""The ``bulbi`` root command group and command registration."""

from __future__ import annotations

from pathlib import Path

import click

from bulbi.cli.commands import COMMANDS
from bulbi.cli.context import AppContext


@click.group()
@click.version_option(package_name="bulbi")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Bulbi -- run coding agents in isolated, spec-defined sandbox environments."""
    if ctx.obj is None:
        ctx.obj = AppContext(project_root=Path.cwd())


for _command in COMMANDS:
    main.add_command(_command.to_click())
