"""Rendering the spec summary and validation results for ``bulbi check``."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from bulbi.cli.render.policy import SHARED_IP_NOTE, PolicyDescriber
from bulbi.cli.render.styles import (
    ALLOWED_STYLE,
    CAUTION_STYLE,
    DENIED_STYLE,
    EMPTY_CELL,
    styled,
)
from bulbi.spec import BulbiSpec
from bulbi.validation import ValidationResult

NOT_SET = "-"


class SpecReportRenderer:
    """Prints one table per spec section, then the validation errors and warnings."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, spec: BulbiSpec, result: ValidationResult) -> None:
        self._console.print(f"\n[bold]Box:[/bold] {spec.box.name}  (agent: {spec.box.agent})\n")
        self._console.print(self._tools_table(spec))
        self._console.print(self._mounts_table(spec))
        self._console.print(self._network_table(spec))
        self._console.print(
            f"[bold]Effective policy:[/bold] {PolicyDescriber().describe(spec.network)}"
        )
        self._console.print(f"[dim]{SHARED_IP_NOTE}[/dim]")
        if spec.profiles:
            self._console.print(self._profiles_table(spec))
        self._console.print(self._limits_table(spec))
        self._print_validation(result)
        self._console.print()

    @staticmethod
    def _tools_table(spec: BulbiSpec) -> Table:
        table = Table(title="Tools")
        table.add_column("Tool", style="cyan")
        for tool in spec.tools.allow or [EMPTY_CELL]:
            table.add_row(tool)
        return table

    @staticmethod
    def _mounts_table(spec: BulbiSpec) -> Table:
        table = Table(title="Mounts")
        table.add_column("Path", style="cyan")
        table.add_column("Mode")
        table.add_column("Excludes", style="dim")
        for mount in spec.mounts:
            style = ALLOWED_STYLE if mount.is_writable else CAUTION_STYLE
            table.add_row(mount.path, styled(mount.mode, style), ", ".join(mount.exclude))
        if not spec.mounts:
            table.add_row(EMPTY_CELL, "", "")
        return table

    @staticmethod
    def _network_table(spec: BulbiSpec) -> Table:
        table = Table(title="Network")
        table.add_column("Setting", style="bold")
        table.add_column("Value")
        table.add_row("Default policy", spec.network.default)
        for rule in spec.network.allow:
            table.add_row("Allow", styled(rule, ALLOWED_STYLE))
        for rule in spec.network.deny:
            table.add_row("Deny", styled(rule, DENIED_STYLE))
        return table

    @staticmethod
    def _profiles_table(spec: BulbiSpec) -> Table:
        table = Table(title="Profiles")
        table.add_column("Name", style="cyan")
        table.add_column("Tools override")
        table.add_column("Network override")
        for name, profile in spec.profiles.items():
            tools = ", ".join(profile.tools.allow) if profile.tools is not None else NOT_SET
            network = (
                f"allow {len(profile.network.allow)} domains"
                if profile.network is not None
                else NOT_SET
            )
            table.add_row(name, tools, network)
        return table

    @staticmethod
    def _limits_table(spec: BulbiSpec) -> Table:
        table = Table(title="Limits")
        table.add_column("Resource", style="bold")
        table.add_column("Value")
        table.add_row("CPU", str(spec.limits.cpu))
        table.add_row("Memory", spec.limits.memory)
        return table

    def _print_validation(self, result: ValidationResult) -> None:
        if result.errors:
            self._console.print("\n[bold red]Errors:[/bold red]")
            for error in result.errors:
                self._console.print(f"  {styled(f'✗ {error}', DENIED_STYLE)}")
        if result.warnings:
            self._console.print("\n[bold yellow]Warnings:[/bold yellow]")
            for warning in result.warnings:
                self._console.print(f"  {styled(f'! {warning}', CAUTION_STYLE)}")
        if not result.errors and not result.warnings:
            self._console.print("\n[green]Spec is valid with no warnings.[/green]")
