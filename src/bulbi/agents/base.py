"""The :class:`Agent` extension point.

To add an agent, subclass :class:`Agent` in its own module under ``bulbi.agents`` and
add an instance to :meth:`bulbi.agents.registry.AgentRegistry.builtin`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from types import MappingProxyType

from bulbi.container.execution import ContainerExecutor


class Agent(ABC):
    """Everything Bulbi needs to install, configure, and launch one coding agent.

    Subclasses must provide :attr:`name` and :attr:`launch_command`; the remaining
    attributes default to "nothing needed" and are overridden as class attributes.
    """

    #: Tool names (from the tool registry) the agent needs, e.g. ``("node",)``.
    required_tools: tuple[str, ...] = ()
    #: Dockerfile ``RUN`` commands that install the agent.
    install_commands: tuple[str, ...] = ()
    #: Environment variables baked into the image and set on the container.
    environment: Mapping[str, str] = MappingProxyType({})
    #: Host environment variables forwarded to the container when set.
    api_key_vars: tuple[str, ...] = ()
    #: Domains the agent needs; suggested in the starter spec's allowlist.
    domains: tuple[str, ...] = ()

    @property
    @abstractmethod
    def name(self) -> str:
        """Name used for ``box.agent`` in the spec."""

    @property
    @abstractmethod
    def launch_command(self) -> tuple[str, ...]:
        """Command ``bulbi run`` executes when no explicit command is given."""

    def api_keys_from(self, host_env: Mapping[str, str]) -> dict[str, str]:
        """The subset of :attr:`api_key_vars` that is set (non-empty) on the host."""
        return {var: host_env[var] for var in self.api_key_vars if host_env.get(var)}

    def prepare_container(  # noqa: B027 - optional hook, intentionally a no-op by default
        self, container: ContainerExecutor, environment: Mapping[str, str]
    ) -> None:
        """Hook run once the container is up, before the agent starts.

        Args:
            container: Executes commands inside the freshly started container.
            environment: The environment the container was started with.
        """


class UnmanagedAgent(Agent):
    """Fallback for agent names Bulbi has no definition for.

    Bulbi installs nothing for it and launches the agent name as a command, so a
    spec can name any program that is already available in the image.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def launch_command(self) -> tuple[str, ...]:
        return (self._name,)
