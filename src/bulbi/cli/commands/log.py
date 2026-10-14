"""``bulbi log``: show the proxy's audit log."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext
from bulbi.cli.render.audit_log import AuditLogRenderer
from bulbi.errors import AuditLogError
from bulbi.proxy import AuditLogReader, audit_log_path


class LogCommand(BulbiCommand):
    name = "log"
    help = "Show proxy log entries (allowed/denied network requests)."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (click.option("--denied", is_flag=True, help="Show only denied requests."),)

    def execute(self, app: AppContext, denied: bool) -> None:
        reader = AuditLogReader(audit_log_path(app.project_root))
        if not reader.exists():
            raise AuditLogError(f"No log file found at {reader.path}. Run a command first.")
        AuditLogRenderer(app.console).render(reader.entries(), denied_only=denied)
