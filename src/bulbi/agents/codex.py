"""OpenAI Codex CLI agent definition."""

from __future__ import annotations

from bulbi.agents.base import Agent
from bulbi.secrets.model import SecretDeclaration
from bulbi.spec import SecretSource

API_KEY_VAR = "OPENAI_API_KEY"


class CodexAgent(Agent):
    """OpenAI's Codex CLI, run in full-auto mode."""

    name = "codex"
    launch_command = ("codex", "--full-auto")
    required_tools = ("node",)
    install_commands = ("npm install -g @openai/codex",)
    secrets = (
        SecretDeclaration(API_KEY_VAR, SecretSource.ENV, API_KEY_VAR, optional=True, builtin=True),
    )
    domains = ("api.openai.com",)
