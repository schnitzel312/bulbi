"""Claude Code agent definition and in-container configuration."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from bulbi.agents.base import Agent
from bulbi.agents.credentials import CredentialProvider, KeychainCredentialProvider
from bulbi.agents.ports import ContainerHandle
from bulbi.constants import CONTAINER_HOME, CONTAINER_WORKSPACE

API_KEY_VAR = "ANTHROPIC_API_KEY"
KEYCHAIN_SERVICE = "Claude Code-credentials"

USER_CONFIG_FILE = ".claude.json"
SETTINGS_FILE = ".claude/settings.json"
CREDENTIALS_FILE = ".claude/.credentials.json"
CREDENTIALS_FILE_MODE = 0o600

# Large enough that Claude Code treats onboarding, tips and migrations as done.
_SEEN_EVERYTHING_COUNT = 9999
_FALLBACK_VERSION = "99.99.99"

JsonObject = dict[str, Any]


class ClaudeAgent(Agent):
    """Anthropic's Claude Code CLI.

    Before launch it writes three files so Claude Code starts without prompts:
    ``~/.claude.json`` (onboarding and workspace trust), ``~/.claude/settings.json``
    (skip the dangerous-mode prompt) and, when no API key is forwarded,
    ``~/.claude/.credentials.json`` with the host's subscription OAuth tokens.
    """

    name = "claude"
    launch_command = ("claude", "--dangerously-skip-permissions")
    required_tools = ("node",)
    install_commands = ("npm install -g @anthropic-ai/claude-code",)
    environment = MappingProxyType(
        {
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_NO_FLICKER": "1",
        }
    )
    api_key_vars = (API_KEY_VAR,)
    domains = (
        "api.anthropic.com",
        "platform.claude.com",
        "claude.ai",
        "console.anthropic.com",
        "sentry.io",
        "statsig.anthropic.com",
        "statsig.com",
    )

    def __init__(
        self,
        credentials: CredentialProvider | None = None,
        host_home: Path | None = None,
    ) -> None:
        self._credentials = credentials or KeychainCredentialProvider.for_host(KEYCHAIN_SERVICE)
        self._host_home = host_home

    def prepare_container(
        self, container: ContainerHandle, environment: Mapping[str, str]
    ) -> None:
        container.write_file(_in_container_home(SETTINGS_FILE), json.dumps(self._settings()))
        container.write_file(
            _in_container_home(USER_CONFIG_FILE),
            json.dumps(self._user_config(self._installed_version(container))),
        )
        if API_KEY_VAR not in environment:
            self._write_credentials(container)

    def _settings(self) -> JsonObject:
        settings = self._read_host_json(SETTINGS_FILE)
        settings["skipDangerousModePermissionPrompt"] = True
        return settings

    def _user_config(self, installed_version: str | None) -> JsonObject:
        config = self._read_host_json(USER_CONFIG_FILE)
        config.update(
            {
                "hasCompletedOnboarding": True,
                "numStartups": max(config.get("numStartups", 0), _SEEN_EVERYTHING_COUNT),
                "lastReleaseNotesSeen": installed_version
                or config.get("lastReleaseNotesSeen", _FALLBACK_VERSION),
                "migrationVersion": max(config.get("migrationVersion", 0), _SEEN_EVERYTHING_COUNT),
            }
        )
        projects = config.setdefault("projects", {})
        projects[CONTAINER_WORKSPACE] = {
            **projects.get(CONTAINER_WORKSPACE, {}),
            "hasTrustDialogAccepted": True,
        }
        return config

    @staticmethod
    def _installed_version(container: ContainerHandle) -> str | None:
        """Version of Claude Code in the image, so its release notes count as seen."""
        result = container.exec(["claude", "--version"])
        words = result.output.split()
        return words[0] if result.succeeded and words else None

    def _write_credentials(self, container: ContainerHandle) -> None:
        credentials = self._credentials.read()
        if credentials:
            container.write_file(
                _in_container_home(CREDENTIALS_FILE), credentials, mode=CREDENTIALS_FILE_MODE
            )

    def _read_host_json(self, relative_path: str) -> JsonObject:
        """Read a JSON object from the host home; missing or malformed files count as empty."""
        path = (self._host_home or Path.home()) / relative_path
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}


def _in_container_home(relative_path: str) -> str:
    return f"{CONTAINER_HOME}/{relative_path}"
