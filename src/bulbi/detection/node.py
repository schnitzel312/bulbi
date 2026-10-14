"""Node.js projects (``package.json``)."""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from bulbi.detection.base import ProjectDetector, read_json_object


class NodeDetector(ProjectDetector):
    language = "node"
    manifest = "package.json"
    tools = ("node",)
    registry_domains = ("registry.npmjs.org", "registry.yarnpkg.com")
    lockfile_tools = MappingProxyType({"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"})

    def read_name(self, manifest_path: Path) -> str | None:
        name = read_json_object(manifest_path).get("name")
        return name if isinstance(name, str) else None
