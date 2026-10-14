"""Generating the Dockerfile for a box."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Iterator

from bulbi.agents import Agent
from bulbi.constants import (
    CONTAINER_HOME,
    CONTAINER_USER,
    CONTAINER_WORKSPACE,
    ENTRYPOINT_PATH,
)
from bulbi.image.entrypoint import EntrypointScript
from bulbi.spec import BulbiSpec
from bulbi.tools import BASE_PACKAGES, ResolvedTool, ToolRegistry

BASE_IMAGE = "debian:bookworm-slim"
_LINE_CONTINUATION = " && \\\n    "

Block = list[str]


class DockerfileBuilder:
    """Renders the Dockerfile for a spec and the agent it runs.

    The image gets the spec's tools, the agent and its required tools, a non-root
    user, and the entrypoint script; apt and dpkg are then removed so nothing else
    can be installed at run time.
    """

    def __init__(self, tools: ToolRegistry) -> None:
        self._tools = tools

    def build(self, spec: BulbiSpec, agent: Agent) -> str:
        spec_tools = self._tools.resolve_all(spec.tools.allow)
        agent_tools = self._missing_agent_tools(agent, spec_tools)
        blocks = [
            [f"FROM {BASE_IMAGE}"],
            self._apt_install_block(spec_tools + agent_tools),
            *self._post_install_blocks(spec_tools, label="{name}"),
            *self._agent_blocks(agent, agent_tools),
            self._user_block(),
            self._entrypoint_block(spec.setup.run),
            self._lockdown_block(),
            self._runtime_block(),
        ]
        return "\n".join(line for block in blocks for line in (*block, ""))

    def _missing_agent_tools(
        self, agent: Agent, spec_tools: list[ResolvedTool]
    ) -> list[ResolvedTool]:
        """Tools the agent needs that the spec does not already allow."""
        present = {tool.name for tool in spec_tools}
        return [self._tools.resolve(name) for name in agent.required_tools if name not in present]

    @staticmethod
    def _apt_install_block(tools: Iterable[ResolvedTool]) -> Block:
        packages = _unique([*BASE_PACKAGES, *(pkg for tool in tools for pkg in tool.packages)])
        return [
            "RUN apt-get update && \\",
            f"    apt-get install -y --no-install-recommends {' '.join(packages)} && \\",
            "    rm -rf /var/lib/apt/lists/*",
        ]

    @staticmethod
    def _post_install_blocks(tools: Iterable[ResolvedTool], label: str) -> Iterator[Block]:
        for tool in tools:
            if tool.post_install:
                yield [
                    f"# post-install: {label.format(name=tool.name)}",
                    f"RUN {_LINE_CONTINUATION.join(tool.post_install)}",
                ]

    def _agent_blocks(self, agent: Agent, agent_tools: list[ResolvedTool]) -> Iterator[Block]:
        if not agent.install_commands:
            return
        yield from self._post_install_blocks(agent_tools, label="{name} (agent dependency)")
        yield [
            f"# Install agent: {agent.name}",
            *(f"RUN {command}" for command in agent.install_commands),
        ]
        if agent.environment:
            yield [f"ENV {key}={value}" for key, value in agent.environment.items()]

    @staticmethod
    def _user_block() -> Block:
        return [
            f"RUN useradd -m -s /bin/bash {CONTAINER_USER}",
            "ENV PIP_BREAK_SYSTEM_PACKAGES=1",
            f"ENV PATH={CONTAINER_HOME}/.local/bin:$PATH",
        ]

    @staticmethod
    def _entrypoint_block(setup_commands: list[str]) -> Block:
        # Base64 avoids having to escape the script for a Dockerfile RUN line.
        script = EntrypointScript(setup_commands).render()
        encoded = base64.b64encode(script.encode()).decode()
        return [
            f"RUN echo '{encoded}' | base64 -d > {ENTRYPOINT_PATH} && chmod +x {ENTRYPOINT_PATH}"
        ]

    @staticmethod
    def _lockdown_block() -> Block:
        return [
            "# Lock down: remove system package manager",
            "RUN rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg && \\",
            "    rm -rf /var/lib/dpkg /var/lib/apt",
        ]

    @staticmethod
    def _runtime_block() -> Block:
        return [
            f"USER {CONTAINER_USER}",
            f"WORKDIR {CONTAINER_WORKSPACE}",
            f'ENTRYPOINT ["{ENTRYPOINT_PATH}"]',
            'CMD ["bash"]',
        ]


def _unique(items: Iterable[str]) -> list[str]:
    """``items`` without duplicates, keeping first-seen order."""
    return list(dict.fromkeys(items))
