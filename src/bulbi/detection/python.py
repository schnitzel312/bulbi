"""Python projects (``pyproject.toml``)."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from bulbi.detection.base import ProjectDetector, read_toml_table


class PythonDetector(ProjectDetector):
    language = "python"
    manifest = "pyproject.toml"
    tools = ("python",)
    registry_domains = ("pypi.org", "files.pythonhosted.org")
    lockfile_tools = MappingProxyType({"poetry.lock": "poetry", "uv.lock": "uv"})

    def read_name(self, manifest_path: Path) -> str | None:
        pyproject = read_toml_table(manifest_path)
        name = pyproject.get("project", {}).get("name") or (
            pyproject.get("tool", {}).get("poetry", {}).get("name")
        )
        return name if isinstance(name, str) else None
