"""The ``bulbi`` subcommands, one class per command."""

from __future__ import annotations

from bulbi.cli.commands.base import BulbiCommand
from bulbi.cli.commands.check import CheckCommand
from bulbi.cli.commands.init import InitCommand
from bulbi.cli.commands.log import LogCommand
from bulbi.cli.commands.ls import ListCommand
from bulbi.cli.commands.reset import ResetCommand
from bulbi.cli.commands.restart import RestartCommand
from bulbi.cli.commands.rm import RemoveCommand
from bulbi.cli.commands.run import RunCommand
from bulbi.cli.commands.shell import ShellCommand
from bulbi.cli.commands.stop import StopCommand

#: Every registered subcommand. Add new BulbiCommand instances here.
COMMANDS: tuple[BulbiCommand, ...] = (
    InitCommand(),
    CheckCommand(),
    RunCommand(),
    ShellCommand(),
    LogCommand(),
    ListCommand(),
    StopCommand(),
    RestartCommand(),
    RemoveCommand(),
    ResetCommand(),
)

__all__ = ["COMMANDS", "BulbiCommand"]
