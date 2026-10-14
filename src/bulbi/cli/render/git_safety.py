"""Rendering git-safety reports (spec §2.4) and quarantine records."""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from bulbi.cli.render.styles import ALLOWED_STYLE, CAUTION_STYLE, DENIED_STYLE, styled
from bulbi.gitsafety.guard import GitSafetyReport
from bulbi.gitsafety.quarantine import QuarantineRecord
from bulbi.spec import GitModeKind, GitSpec

GUARDED_RESIDUAL = (
    "Guarded git: Bulbi scans the checkouts for git metadata that would run code on this "
    "machine after every session and before every attach. While sessions are live, run "
    "git for this project inside the box (`bulbi shell`) or run `bulbi git-scan` first; "
    'for a full guarantee use [git] mode = "isolated".'
)
ISOLATED_NOTE = (
    "Isolated git: the box has its own small git dir (a volume of a few MB: refs, index "
    "and its new commits) and reads history from this repository's objects read-only; "
    "it never sees this repository's config, hooks or refs. `bulbi pull` fetches its "
    "branches as bulbi/<branch> from a bundle. New .git entries in the working tree are "
    "still scanned for."
)


def describe_git(settings: GitSpec) -> str:
    return ISOLATED_NOTE if settings.mode is GitModeKind.ISOLATED else GUARDED_RESIDUAL


class GitReportRenderer:
    """Names every file and key, what was done, and how to undo it."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def render(self, report: GitSafetyReport, *, show_clean: bool = False) -> None:
        if report.clean:
            if show_clean:
                self._console.print(styled("✓ No dangerous git metadata found.", ALLOWED_STYLE))
            return
        if report.findings:
            self._console.print(
                styled(
                    f"✗ Git safety: {len(report.findings)} change(s) that could run code on "
                    "this machine when you use git:",
                    f"bold {DENIED_STYLE}",
                )
            )
        for outcome in report.outcomes:
            finding = outcome.finding
            style = ALLOWED_STYLE if outcome.neutralised else DENIED_STYLE
            self._console.print(
                f"  [{DENIED_STYLE}]•[/{DENIED_STYLE}] {escape(str(finding.path))}\n"
                f"      {escape(finding.describe())} [dim]({finding.reason})[/dim]\n"
                f"      → {styled(escape(outcome.done), style)}"
            )
        if report.record_id:
            self._console.print(
                f"  [bold]Restore with:[/bold] bulbi git-restore {report.record_id}"
            )
        if not report.complete:
            self._console.print(
                styled(
                    f"✗ The git safety scan stopped after {report.budget} (scan_budget); "
                    "some directories were not checked.",
                    f"bold {DENIED_STYLE}",
                )
            )

    def render_records(self, records: Sequence[QuarantineRecord]) -> None:
        if not records:
            self._console.print("[dim]Nothing is quarantined.[/dim]")
            return
        table = Table(title="Quarantined git metadata")
        table.add_column("Id", style="cyan")
        table.add_column("State")
        table.add_column("Items")
        for record in records:
            state = (
                styled("restored", ALLOWED_STYLE)
                if record.restored
                else styled("quarantined", CAUTION_STYLE)
            )
            items = "\n".join(
                f"{item.original} ({item.reason}{', ' + item.detail if item.detail else ''})"
                for item in record.items
            )
            table.add_row(record.id, state, escape(items))
        self._console.print(table)
