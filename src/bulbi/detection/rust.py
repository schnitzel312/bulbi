"""Rust projects (``Cargo.toml``)."""

from __future__ import annotations

from pathlib import Path

from bulbi.detection.base import ProjectDetector, read_toml_table


class RustDetector(ProjectDetector):
    language = "rust"
    manifest = "Cargo.toml"
    tools = ("rust", "cargo")
    registry_domains = ("crates.io", "static.crates.io")

    def read_name(self, manifest_path: Path) -> str | None:
        name = read_toml_table(manifest_path).get("package", {}).get("name")
        return name if isinstance(name, str) else None
