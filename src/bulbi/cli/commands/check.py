"""``bulbi check``: validate the spec and summarise what the box can do."""

from __future__ import annotations

import click

from bulbi.cli.commands.base import BulbiCommand
from bulbi.cli.context import AppContext
from bulbi.cli.render.spec_report import SpecReportRenderer
from bulbi.secrets import SecretPlan, user_declarations


class CheckCommand(BulbiCommand):
    name = "check"
    help = "Validate the spec and show what the box can/cannot do (exit 1 on errors)."

    def execute(self, app: AppContext) -> None:
        spec = app.load_spec()
        result = app.validator.validate(spec)
        plan = SecretPlan(app.agent_for(spec).secrets, user_declarations(spec.secrets))
        statuses = plan.statuses(app.secret_readers)
        SpecReportRenderer(app.console).render(spec, result, statuses)
        if not result.ok:
            click.get_current_context().exit(1)
