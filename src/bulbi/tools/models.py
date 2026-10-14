"""Value objects describing installable tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from bulbi.tools.installers import APT_INSTALLER, ToolInstaller


class ToolReference(NamedTuple):
    """A parsed ``name[@version]`` reference from the spec."""

    name: str
    version: str | None


@dataclass(frozen=True)
class ToolDefinition:
    """How to install one tool on the Debian base image.

    Attributes:
        name: Name used in ``tools.allow``.
        packages: apt packages the installer works from.
        verify_cmd: Command that proves the tool works.
        post_install: Shell commands the installer runs after the apt install.
        default_version: Version reported when the spec does not pin one.
        allowed_versions: Versions a spec may pin; empty means any pin is accepted.
        installer: Strategy that turns this definition into packages and commands.
    """

    name: str
    packages: tuple[str, ...]
    verify_cmd: str
    post_install: tuple[str, ...] = ()
    default_version: str | None = None
    allowed_versions: tuple[str, ...] = ()
    installer: ToolInstaller = APT_INSTALLER

    def supports_version(self, version: str) -> bool:
        return not self.allowed_versions or version in self.allowed_versions


@dataclass(frozen=True)
class ResolvedTool:
    """A tool reference resolved, via its installer, into what the image needs."""

    name: str
    version: str | None
    packages: list[str]
    post_install: list[str]
    verify_cmd: str
