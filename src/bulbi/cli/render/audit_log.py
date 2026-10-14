"""Rendering the proxy audit log for ``bulbi log``."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from bulbi.cli.render.styles import ALLOWED_STYLE, DENIED_STYLE, styled
from bulbi.proxy import LogEntry


class AuditLogRenderer:
    """Prints log entries as a table, followed by allowed/denied totals."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, entries: list[LogEntry], *, denied_only: bool = False) -> None:
        shown = [entry for entry in entries if entry.denied or not denied_only]
        self._console.print(self._table(shown))
        denied_count = sum(entry.denied for entry in entries)
        self._console.print(f"\n[dim]{len(entries)} total entries, {denied_count} denied[/dim]\n")

    @staticmethod
    def _table(entries: list[LogEntry]) -> Table:
        table = Table(title="Proxy Log")
        table.add_column("Time", style="dim")
        table.add_column("Domain")
        table.add_column("Action")
        table.add_column("Method", style="bold")
        table.add_column("URL")
        for entry in entries:
            style = DENIED_STYLE if entry.denied else ALLOWED_STYLE
            table.add_row(
                entry.timestamp, entry.domain, styled(entry.action, style), entry.method, entry.url
            )
        return table
