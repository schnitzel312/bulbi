"""The :class:`Agent` extension point.

To add an agent, subclass :class:`Agent` in its own module under ``bulbi.agents`` and
add an instance to :meth:`bulbi.agents.registry.AgentRegistry.builtin`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from types import MappingProxyType

from bulbi.agents.ports import BoxContext, ContainerHandle
from bulbi.secrets.model import SecretDeclaration


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
    #: Built-in secrets (e.g. API keys, OAuth files); a user's [secrets] entry with the
    #: same name overrides one (spec §10.2).
    secrets: tuple[SecretDeclaration, ...] = ()
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

    def prepare_container(  # noqa: B027 - optional hook, intentionally a no-op by default
        self, container: ContainerHandle, context: BoxContext
    ) -> None:
        """Hook run once per container start, before any session runs.

        Args:
            container: Runs commands and writes files inside the freshly started box.
            context: The session environment and the project's checkout paths.
        """

    def refresh(  # noqa: B027 - optional hook, intentionally a no-op by default
        self, container: ContainerHandle, context: BoxContext
    ) -> None:
        """Hook run when a session attaches to an already running box.

        Live sessions may be using the box, so implementations must only update what is
        safe to change underneath them (e.g. credentials, or one key of a config file).
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
