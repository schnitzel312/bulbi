"""``bulbi pull``: bring the box's commits back (``[git] mode = "isolated"``)."""

from __future__ import annotations

from collections.abc import Sequence

import click
from rich.markup import escape

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.commands.sandbox import profile_option
from bulbi.cli.context import AppContext
from bulbi.container.execstream import DockerExecStream
from bulbi.errors import GitSafetyError
from bulbi.gitsafety.isolated import PULL_NAMESPACE, BundlePuller
from bulbi.spec import GitModeKind


class PullCommand(BulbiCommand):
    name = "pull"
    help = (
        f"Fetch the box's branches (isolated git mode) into {PULL_NAMESPACE}/*, as a git "
        "bundle: host git never opens the box's repository."
    )

    def parameters(self) -> Sequence[ClickDecorator]:
        return (
            click.option("--branch", default=None, help="Fetch only this branch."),
            profile_option,
        )

    def execute(self, app: AppContext, branch: str | None, profile: str | None) -> None:
        spec = app.load_spec(profile)
        if spec.git.mode is not GitModeKind.ISOLATED:
            raise GitSafetyError(
                'bulbi pull needs [git] mode = "isolated"; in guarded mode the box commits '
                "straight to this repository"
            )
        box = app.orchestrator(spec, profile).running_box()
        puller = BundlePuller(DockerExecStream(app.docker, box.id), app.project)
        result = puller.pull(branch)
        for ref in result.refs:
            app.console.print(f"[green]✓[/green] {escape(ref)}")
        if not result.refs:
            app.console.print("[dim]The box has no branches.[/dim]")
