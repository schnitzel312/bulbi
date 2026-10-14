"""Lookup of agents by the name used in ``box.agent``."""

from __future__ import annotations

from collections.abc import Iterable

from bulbi.agents.base import Agent, UnmanagedAgent
from bulbi.agents.claude import ClaudeAgent
from bulbi.agents.codex import CodexAgent


class AgentRegistry:
    """The agents Bulbi knows how to install and configure."""

    def __init__(self, agents: Iterable[Agent]) -> None:
        self._agents = {agent.name: agent for agent in agents}

    @classmethod
    def builtin(cls) -> AgentRegistry:
        return cls([ClaudeAgent(), CodexAgent()])

    @property
    def names(self) -> list[str]:
        return sorted(self._agents)

    def resolve(self, name: str) -> Agent:
        """The registered agent called ``name``, or an :class:`UnmanagedAgent` for it."""
        return self._agents.get(name) or UnmanagedAgent(name)
