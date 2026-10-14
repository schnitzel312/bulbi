"""Tools that can be installed into a box."""

from __future__ import annotations

from bulbi.tools.catalog import BASE_PACKAGES, BUILTIN_TOOLS
from bulbi.tools.installers import APT_INSTALLER, AptInstaller, ToolInstaller
from bulbi.tools.models import ResolvedTool, ToolDefinition, ToolReference
from bulbi.tools.registry import ToolRegistry

__all__ = [
    "APT_INSTALLER",
    "BASE_PACKAGES",
    "BUILTIN_TOOLS",
    "AptInstaller",
    "ResolvedTool",
    "ToolDefinition",
    "ToolInstaller",
    "ToolReference",
    "ToolRegistry",
]
