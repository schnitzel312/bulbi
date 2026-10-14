"""``bulbi check``: validate the spec and summarise what the box can do."""

from __future__ import annotations

from bulbi.cli.commands.base import BulbiCommand
from bulbi.cli.context import AppContext
from bulbi.cli.render.spec_report import SpecReportRenderer


class CheckCommand(BulbiCommand):
    name = "check"
    help = "Validate the spec and show what the box can/cannot do."

    def execute(self, app: AppContext) -> None:
        spec = app.load_spec()
        SpecReportRenderer(app.console).render(spec, app.validator.validate(spec))
