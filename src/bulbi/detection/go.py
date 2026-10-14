"""Go projects (``go.mod``)."""

from __future__ import annotations

from pathlib import Path

from bulbi.detection.base import ProjectDetector


class GoDetector(ProjectDetector):
    language = "go"
    manifest = "go.mod"
    tools = ("go",)
    registry_domains = ("proxy.golang.org", "sum.golang.org")

    def read_name(self, manifest_path: Path) -> str | None:
        return None  # The module path is not a box name; use the directory name.
