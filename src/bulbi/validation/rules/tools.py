"""Rules about the tools a spec allows."""

from __future__ import annotations

from collections.abc import Iterator

from bulbi.errors import ToolError
from bulbi.spec import BulbiSpec
from bulbi.tools import ToolRegistry
from bulbi.validation.base import ValidationIssue, ValidationRule

# Tools that can open sockets and read any mounted file on their own.
INTERPRETER_TOOLS = frozenset({"python", "node", "bun", "ruby"})


class KnownToolsRule(ValidationRule):
    """Every allowed tool must resolve in the tool registry (name and pinned version)."""

    def __init__(self, tools: ToolRegistry) -> None:
        self._tools = tools

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        for reference in spec.tools.allow:
            try:
                self._tools.resolve(reference)
            except ToolError as exc:
                yield ValidationIssue.error(str(exc))


class InterpreterToolsRule(ValidationRule):
    """Warn that general-purpose interpreters make network and mounts the real boundary."""

    def check(self, spec: BulbiSpec) -> Iterator[ValidationIssue]:
        interpreters = sorted(INTERPRETER_TOOLS & self._allowed_names(spec))
        if interpreters:
            yield ValidationIssue.warning(
                f"interpreters allowed ({', '.join(interpreters)}): "
                "these can open sockets and read mounted files. "
                "The network and mount rules are the real security boundary"
            )

    @staticmethod
    def _allowed_names(spec: BulbiSpec) -> set[str]:
        names = set()
        for reference in spec.tools.allow:
            try:
                names.add(ToolRegistry.parse(reference).name)
            except ToolError:
                continue  # Reported by KnownToolsRule.
        return names
