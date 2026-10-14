"""The :class:`ProjectDetector` extension point used by ``bulbi init``.

To support a new ecosystem, subclass :class:`ProjectDetector` in its own module and
add an instance to :meth:`bulbi.detection.registry.DetectorRegistry.builtin`.
"""

from __future__ import annotations

import json
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

# Every starter spec gets these, whatever the ecosystem.
COMMON_TOOLS: tuple[str, ...] = ("git", "rg")


@dataclass(frozen=True)
class DetectedProject:
    """What ``bulbi init`` learned about a project."""

    name: str
    language: str | None
    tools: tuple[str, ...]
    registry_domains: tuple[str, ...] = ()


class ProjectDetector(ABC):
    """Recognises one ecosystem by its manifest file and describes the project.

    Subclasses set the class attributes and implement :meth:`read_name`.
    """

    #: Language label shown in the starter spec.
    language: str
    #: File whose presence identifies the ecosystem, e.g. ``pyproject.toml``.
    manifest: str
    #: Ecosystem tools placed before :data:`COMMON_TOOLS`.
    tools: tuple[str, ...] = ()
    #: Package-registry domains the project needs.
    registry_domains: tuple[str, ...] = ()
    #: Lockfile name -> extra tool it implies, e.g. ``{"uv.lock": "uv"}``.
    lockfile_tools: Mapping[str, str] = MappingProxyType({})

    def matches(self, project_root: Path) -> bool:
        return (project_root / self.manifest).exists()

    def detect(self, project_root: Path) -> DetectedProject:
        return DetectedProject(
            name=self.read_name(project_root / self.manifest) or project_root.resolve().name,
            language=self.language,
            tools=(*self.tools, *COMMON_TOOLS, *self._lockfile_tools(project_root)),
            registry_domains=self.registry_domains,
        )

    @abstractmethod
    def read_name(self, manifest_path: Path) -> str | None:
        """Project name declared in the manifest, or ``None`` to use the directory name."""

    def _lockfile_tools(self, project_root: Path) -> list[str]:
        return [
            tool
            for lockfile, tool in self.lockfile_tools.items()
            if (project_root / lockfile).exists()
        ]


def read_toml_table(path: Path) -> dict[str, Any]:
    """Parse a TOML file, treating unreadable or malformed files as empty."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def read_json_object(path: Path) -> dict[str, Any]:
    """Parse a JSON object file, treating unreadable, malformed, or non-object files as empty."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}
