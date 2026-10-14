"""Audit log utilities for the bulbi network proxy."""

from __future__ import annotations

from pathlib import Path

from rich.table import Table

from bulbi.constants import LOG_DIR, LOG_FILENAME


def get_log_path(project_root: Path) -> Path:
    """Return the path to the proxy log file."""
    return project_root / LOG_DIR / LOG_FILENAME


def ensure_log_dir(project_root: Path) -> None:
    """Create the .bulbi/ directory if it does not exist."""
    log_dir = project_root / LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)


def format_log_table(entries: list[dict], *, denied_only: bool = False) -> Table:
    """Build a Rich Table showing proxy log entries.

    Each entry dict is expected to have keys:
        timestamp, domain, action ("allow" | "deny"), method, url
    """
    table = Table(title="Proxy Log")
    table.add_column("Time", style="dim")
    table.add_column("Domain")
    table.add_column("Action")
    table.add_column("Method", style="bold")
    table.add_column("URL")

    for entry in entries:
        action = entry.get("action", "")
        if denied_only and action != "deny":
            continue

        style = "red" if action == "deny" else "green"
        table.add_row(
            entry.get("timestamp", ""),
            entry.get("domain", ""),
            f"[{style}]{action}[/{style}]",
            entry.get("method", ""),
            entry.get("url", ""),
        )

    return table
