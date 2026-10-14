"""Console progress output for sandbox sessions."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console

from bulbi.sandbox import SandboxObserver
from bulbi.spec import BulbiSpec


class ConsoleSandboxObserver(SandboxObserver):
    """Prints each sandbox step to the console."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def building_image(self, spec: BulbiSpec) -> None:
        self._console.print(f"[bold]Building image for [cyan]{spec.box.name}[/cyan]...[/bold]")

    def starting_container(self) -> None:
        self._console.print("[bold]Starting container...[/bold]")

    def running(self, label: str, command: Sequence[str]) -> None:
        self._console.print(f"[bold]{label}:[/bold] {' '.join(command)}")
