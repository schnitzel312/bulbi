"""Installation strategies for tools.

Each :class:`~bulbi.tools.models.ToolDefinition` names the installer that turns it into
system packages and post-install shell commands. To install a tool differently (for
example an exact interpreter version), subclass :class:`ToolInstaller` and set it as
that definition's ``installer`` in the catalog. The registry and the Dockerfile builder
only consume the resulting :class:`~bulbi.tools.models.ResolvedTool`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bulbi.tools.models import ToolDefinition


class ToolInstaller(ABC):
    """Decides how a tool definition is installed for a requested version."""

    @abstractmethod
    def system_packages(self, tool: ToolDefinition, version: str | None) -> tuple[str, ...]:
        """apt packages the image must contain for this tool."""

    @abstractmethod
    def install_commands(self, tool: ToolDefinition, version: str | None) -> tuple[str, ...]:
        """Shell commands run (as root, at image build) after the apt install."""


class AptInstaller(ToolInstaller):
    """Installs the Debian-packaged tool plus the definition's post-install commands.

    TODO(bulbi): the requested version is ignored. Debian bookworm ships fixed versions,
    so ``python@3.12`` installs Debian's Python 3.11 and ``node@22`` installs Node 18.
    A version-pinned installer (e.g. ``uv python install`` or official Node builds)
    should be added as a separate ToolInstaller and selected in the tool catalog.
    """

    def system_packages(self, tool: ToolDefinition, version: str | None) -> tuple[str, ...]:
        return tool.packages

    def install_commands(self, tool: ToolDefinition, version: str | None) -> tuple[str, ...]:
        return tool.post_install


APT_INSTALLER = AptInstaller()
