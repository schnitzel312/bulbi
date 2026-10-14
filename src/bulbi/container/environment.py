"""The environment variables a box is started with."""

from __future__ import annotations

import os
from collections.abc import Mapping

from bulbi.agents import Agent


class EnvironmentBuilder:
    """Builds a box's environment: the agent's variables and forwarded API keys.

    No proxy variables: the gateway enforces the network policy in the kernel, so tools
    need no configuration (spec §3.1).
    """

    def __init__(self, host_env: Mapping[str, str] | None = None) -> None:
        self._host_env = os.environ if host_env is None else host_env

    def build(self, agent: Agent) -> dict[str, str]:
        return {**agent.environment, **agent.api_keys_from(self._host_env)}
