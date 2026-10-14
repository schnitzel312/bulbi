"""Rendering the commented starter ``bulbi.toml`` written by ``bulbi init``."""

from __future__ import annotations

import json
from collections.abc import Iterable

from bulbi.agents import Agent
from bulbi.constants import DEFAULT_CPU, DEFAULT_MEMORY, SPEC_VERSION
from bulbi.detection.base import DetectedProject
from bulbi.spec import MountMode, NetworkDefault

_DEFAULT_EXCLUDES = (".env", "*.pem", "*.key")


class StarterSpecRenderer:
    """Renders a starter spec for a detected project and the agent it will run."""

    def __init__(self, agent: Agent) -> None:
        self._agent = agent

    def render(self, project: DetectedProject) -> str:
        domains = (*project.registry_domains, *self._agent.domains)
        language_note = (
            f"Detected: {project.language} project"
            if project.language
            else "No specific language detected"
        )
        lines = [
            "# Bulbi spec — defines the sandbox environment for coding agents.",
            "# Docs: https://github.com/anthropics/bulbi",
            "",
            "# Spec format version (do not change).",
            f"spec = {_toml_string(SPEC_VERSION)}",
            "",
            "# ---- Box identity ---------------------------------------------------",
            "[box]",
            f"name = {_toml_string(project.name)}",
            f"agent = {_toml_string(self._agent.name)}",
            "",
            "# ---- Tools installed in the container --------------------------------",
            "[tools]",
            f"allow = {_toml_array(project.tools)}  # {language_note}",
            "",
            "# ---- Setup commands run once, at first container start ---------------",
            "[setup]",
            "run = []",
            "",
            "# ---- Filesystem mounts ----------------------------------------------",
            "# Mount the project directory read-write, excluding secrets.",
            "[[mount]]",
            'path = "."',
            f"mode = {_toml_string(MountMode.READ_WRITE)}",
            f"exclude = {_toml_array(_DEFAULT_EXCLUDES)}",
            "",
            "# ---- Network access -------------------------------------------------",
            "# Default deny: only the domains listed below are reachable.",
            "[network]",
            f"default = {_toml_string(NetworkDefault.DENY)}",
            f"allow = {_toml_array(domains)}",
            "",
            "# ---- Secrets (optional) ----------------------------------------------",
            "# One line per secret. The agent can read them; the network policy limits",
            "# where it can send them. `bulbi check` lists everything entering the box.",
            "# [secrets]",
            '# GITHUB_TOKEN = { from = "env" }',
            '# NPM_TOKEN    = { from = "command", source = "op read op://dev/npm/token" }',
            '# NPM_RC       = { from = "file", source = "~/.npmrc", to = "file", '
            'path = "~/.npmrc" }',
            "",
            "# ---- Resource limits ------------------------------------------------",
            "[limits]",
            f"cpu = {DEFAULT_CPU}",
            f"memory = {_toml_string(DEFAULT_MEMORY)}",
            "",
            "# ---- Profiles (optional) --------------------------------------------",
            "# Profiles narrow the root spec. Uncomment to define a read-only profile.",
            "# [profiles.readonly]",
            "# [profiles.readonly.mounts]",
            f'# "." = {_toml_string(MountMode.READ_ONLY)}',
            "",
        ]
        return "\n".join(lines)


def _toml_string(value: str) -> str:
    """A TOML basic string (JSON string escapes are valid TOML escapes)."""
    return json.dumps(str(value), ensure_ascii=False)


def _toml_array(values: Iterable[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"
