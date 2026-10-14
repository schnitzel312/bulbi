"""The :class:`BulbiCommand` extension point.

To add a CLI command, subclass :class:`BulbiCommand` in its own module under
``bulbi.cli.commands`` and add an instance to ``COMMANDS`` in ``bulbi.cli.commands``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from typing import Any, ClassVar

import click

from bulbi.cli.context import AppContext
from bulbi.errors import BulbiError

ClickDecorator = Callable[[Callable[..., Any]], Callable[..., Any]]


class BulbiCommand(ABC):
    """One ``bulbi`` subcommand: its name, help, Click parameters, and behaviour."""

    name: ClassVar[str]
    help: ClassVar[str]

    def parameters(self) -> Sequence[ClickDecorator]:
        """Click option/argument decorators, in the order they appear in ``--help``."""
        return ()

    @abstractmethod
    def execute(self, app: AppContext, *args: Any, **options: Any) -> None:
        """Run the command; ``options`` are the parsed Click parameters."""

    def to_click(self) -> click.Command:
        """Build the Click command; any :class:`BulbiError` becomes a clean CLI error."""

        @click.pass_obj
        def callback(app: AppContext, /, **options: Any) -> None:
            try:
                self.execute(app, **options)
            except BulbiError as exc:
                raise click.ClickException(str(exc)) from exc

        decorated: Callable[..., Any] = callback
        for parameter in reversed(self.parameters()):
            decorated = parameter(decorated)
        return click.command(self.name, help=self.help)(decorated)
