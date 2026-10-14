"""OpenAI Codex CLI agent definition."""

from __future__ import annotations

from bulbi.agents.base import Agent


class CodexAgent(Agent):
    """OpenAI's Codex CLI, run in full-auto mode."""

    name = "codex"
    launch_command = ("codex", "--full-auto")
    required_tools = ("node",)
    install_commands = ("npm install -g @openai/codex",)
    api_key_vars = ("OPENAI_API_KEY",)
    domains = ("api.openai.com",)
