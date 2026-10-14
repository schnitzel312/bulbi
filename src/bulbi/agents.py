"""Agent runtime definitions.

Each supported agent (claude, codex, etc.) has its configuration
centralized here: install commands, env vars, API key env vars,
required network domains, and credential helpers.
"""

from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentConfig:
    """Everything Bulbi needs to know about an agent runtime."""

    requires: list[str] = field(default_factory=list)
    install_cmds: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    api_key_vars: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)


AGENTS: dict[str, AgentConfig] = {
    "claude": AgentConfig(
        requires=["node"],
        install_cmds=["npm install -g @anthropic-ai/claude-code"],
        command=["claude", "--dangerously-skip-permissions"],
        env={
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "CLAUDE_CODE_NO_FLICKER": "1",
        },
        api_key_vars=["ANTHROPIC_API_KEY"],
        domains=[
            "api.anthropic.com",
            "platform.claude.com",
            "claude.ai",
            "console.anthropic.com",
            "sentry.io",
            "statsig.anthropic.com",
            "statsig.com",
        ],
    ),
    "codex": AgentConfig(
        requires=["node"],
        install_cmds=["npm install -g @openai/codex"],
        command=["codex", "--full-auto"],
        env={},
        api_key_vars=["OPENAI_API_KEY"],
        domains=["api.openai.com"],
    ),
}


def get_agent_config(agent_name: str) -> AgentConfig | None:
    """Look up the agent config by name, or None if unknown."""
    return AGENTS.get(agent_name)


def get_claude_credentials_json() -> str | None:
    """Extract Claude OAuth credentials JSON from the macOS Keychain.

    On macOS, Claude Code stores subscription OAuth tokens in the system
    Keychain under 'Claude Code-credentials'. On Linux (inside Docker),
    Claude Code reads from ~/.claude/.credentials.json instead.

    Returns the raw JSON string, or None if unavailable.
    """
    if platform.system() != "Darwin":
        return None
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", "Claude Code-credentials", "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        # Validate it's actually JSON before returning.
        json.loads(result.stdout.strip())
        return result.stdout.strip()
    except Exception:
        return None
