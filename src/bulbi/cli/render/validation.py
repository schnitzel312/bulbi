"""Rendering validation errors and warnings (shared by ``check``, ``run`` and ``shell``)."""

from __future__ import annotations

from rich.console import Console

from bulbi.cli.render.styles import CAUTION_STYLE, DENIED_STYLE, styled
from bulbi.validation import ValidationResult


class ValidationRenderer:
    """Prints errors, then warnings; or a success line when there is neither."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, result: ValidationResult, *, show_success: bool = True) -> None:
        if result.errors:
            self._console.print("\n[bold red]Errors:[/bold red]")
            for error in result.errors:
                self._console.print(f"  {styled(f'✗ {error}', DENIED_STYLE)}")
        if result.warnings:
            self._console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in result.warnings:
                self._console.print(f"  {styled(f'! {warning}', CAUTION_STYLE)}")
        if show_success and not result.errors and not result.warnings:
            self._console.print("\n[green]Spec is valid with no warnings.[/green]")
