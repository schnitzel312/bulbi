"""The environment variables a box is started with."""

from __future__ import annotations

import os
import platform
from collections.abc import Mapping

from bulbi.agents import Agent
from bulbi.constants import MACOS_SYSTEM_NAME

PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
DOCKER_DESKTOP_HOST = "host.docker.internal"
# TODO(bulbi): on Linux the container is pointed at the docker0 bridge address, but the
# proxy binds 127.0.0.1 (PROXY_BIND_HOST), so it is unreachable from the container.
# Fixing it means binding the proxy to the bridge (or 0.0.0.0) and is a security
# decision left to the maintainers; see the refactor log.
DOCKER_BRIDGE_GATEWAY = "172.17.0.1"


class EnvironmentBuilder:
    """Builds a box's environment: proxy settings, agent variables, and API keys."""

    def __init__(
        self, host_env: Mapping[str, str] | None = None, system: str | None = None
    ) -> None:
        self._host_env = os.environ if host_env is None else host_env
        self._system = system or platform.system()

    @property
    def proxy_host(self) -> str:
        """How the container reaches the host, where the proxy runs."""
        return DOCKER_DESKTOP_HOST if self._system == MACOS_SYSTEM_NAME else DOCKER_BRIDGE_GATEWAY

    def build(self, agent: Agent, proxy_port: int) -> dict[str, str]:
        proxy_url = f"http://{self.proxy_host}:{proxy_port}"
        return {
            **dict.fromkeys(PROXY_VARIABLES, proxy_url),
            **agent.environment,
            **agent.api_keys_from(self._host_env),
        }
