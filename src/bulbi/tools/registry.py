"""The tool registry: single source of truth for parsing and resolving tool references."""

from __future__ import annotations

import re
from collections.abc import Iterable

from bulbi.errors import ToolError
from bulbi.tools.catalog import BUILTIN_TOOLS
from bulbi.tools.models import ResolvedTool, ToolDefinition, ToolReference

_TOOL_REFERENCE_PATTERN = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*)(?:@(.+))?$")


class ToolRegistry:
    """Known tool definitions, and resolution of spec references against them."""

    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        self._definitions = {definition.name: definition for definition in definitions}

    @classmethod
    def builtin(cls) -> ToolRegistry:
        return cls(BUILTIN_TOOLS)

    @property
    def names(self) -> list[str]:
        return sorted(self._definitions)

    @staticmethod
    def parse(reference: str) -> ToolReference:
        """Parse ``name[@version]``."""
        match = _TOOL_REFERENCE_PATTERN.match(reference)
        if not match:
            raise ToolError(f"invalid tool spec: '{reference}'")
        return ToolReference(match.group(1), match.group(2))

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._definitions[name]
        except KeyError:
            raise ToolError(
                f"unknown tool: '{name}'. Available: {', '.join(self.names)}"
            ) from None

    def resolve(self, reference: str) -> ResolvedTool:
        """Resolve a reference such as ``python@3.12``, validating any pinned version."""
        name, version = self.parse(reference)
        definition = self.get(name)
        if version and not definition.supports_version(version):
            raise ToolError(
                f"unsupported version '{version}' for {name}. "
                f"Available: {', '.join(definition.allowed_versions)}"
            )
        effective_version = version or definition.default_version
        installer = definition.installer
        return ResolvedTool(
            name=name,
            version=effective_version,
            packages=list(installer.system_packages(definition, effective_version)),
            post_install=list(installer.install_commands(definition, effective_version)),
            verify_cmd=definition.verify_cmd,
        )

    def resolve_all(self, references: Iterable[str]) -> list[ResolvedTool]:
        return [self.resolve(reference) for reference in references]
