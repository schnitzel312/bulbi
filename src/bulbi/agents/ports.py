"""What an agent's ``prepare_container`` hook may do inside a box.

``bulbi.agents`` owns this interface and ``bulbi.container`` implements it with Docker,
so agents never depend on container infrastructure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_FILE_MODE = 0o644


@dataclass(frozen=True)
class ExecResult:
    """Outcome of a command run inside a container."""

    exit_code: int
    output: str

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0


class ContainerHandle(ABC):
    """A started box, seen from inside: run commands as the sandbox user and write its files."""

    @abstractmethod
    def exec(self, argv: Sequence[str]) -> ExecResult:
        """Run ``argv`` and wait for it to finish."""

    @abstractmethod
    def write_file(self, path: str, content: str, *, mode: int = DEFAULT_FILE_MODE) -> None:
        """Create or replace ``path`` and its parent directories, owned by the sandbox user.

        ``path`` must be absolute and inside the sandbox user's home directory; anything
        else raises :class:`~bulbi.errors.SandboxError`. Implementations may write with
        more privilege than the user has, which is why the location is restricted.
        """
