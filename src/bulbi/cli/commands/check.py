"""``bulbi check``: validate the spec and summarise what the box can do."""

from __future__ import annotations

from collections.abc import Sequence

import click

from bulbi.cli.commands.base import BulbiCommand, ClickDecorator
from bulbi.cli.context import AppContext
from bulbi.cli.render.spec_report import SpecReportRenderer
from bulbi.secrets import SecretPlan, user_declarations


class CheckCommand(BulbiCommand):
    name = "check"
    help = "Validate the spec and show what the box can/cannot do (exit 1 on errors)."

    def parameters(self) -> Sequence[ClickDecorator]:
        return (
            click.option(
                "--probe-secrets",
                is_flag=True,
                help="Also resolve command and keychain secrets (runs them on this machine).",
            ),
        )

    def execute(self, app: AppContext, probe_secrets: bool) -> None:
        spec = app.load_spec()
        result = app.validator.validate(spec)
        plan = SecretPlan(app.agent_for(spec).secrets, user_declarations(spec.secrets))
        statuses = plan.statuses(app.secret_readers, probe_all=probe_secrets)
        SpecReportRenderer(app.console).render(spec, result, statuses)
        if not result.ok:
            click.get_current_context().exit(1)
