"""``bulbi stop``: stop the project's box and gateway (kept for a fast restart)."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.commands.sandbox import confirm_ending_sessions, profile_option, yes_option
from bulbi.cli.context import AppContext


class StopCommand(BulbiCommand):
    name = "stop"
    help = "Stop this project's box and gateway (use --all for every box)."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (
            profile_option,
            click.option("--all", "all_boxes", is_flag=True, help="Stop every bulbi box."),
            yes_option,
        )

    def execute(self, app: AppContext, profile: str | None, all_boxes: bool, yes: bool) -> None:
        if all_boxes:
            self._stop_all(app, yes)
            return
        orchestrator = app.orchestrator(app.load_spec(profile), profile)
        confirm_ending_sessions(orchestrator.active_sessions(), yes)
        if orchestrator.stop():
            app.console.print(f"[green]Stopped {orchestrator.identity.name}[/green]")
        else:
            app.console.print("[dim]No box for this project.[/dim]")

    @staticmethod
    def _stop_all(app: AppContext, yes: bool) -> None:
        boxes, gateways, tracker = app.box_manager(), app.gateway_manager(), app.session_tracker()
        states = boxes.list_containers()
        running = [s for s in states if not s.is_gateway and s.running]
        confirm_ending_sessions(sum(tracker.active_sessions(s.id) for s in running), yes)
        for state in states:
            if not state.is_gateway:
                boxes.stop(state.id)
        gateways.reap(boxes.list_containers())
        app.console.print(f"[green]Stopped {len(running)} box(es).[/green]")
