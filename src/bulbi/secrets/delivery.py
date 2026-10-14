"""Getting secret values into the box, one delivery per ``to`` kind (spec §10.3).

To add a delivery (e.g. ``inject``), subclass :class:`SecretDelivery` and register it in
:meth:`SecretDeliveries.builtin`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping

from bulbi.agents.ports import ContainerHandle
from bulbi.constants import CONTAINER_HOME
from bulbi.errors import SandboxError
from bulbi.paths import expand_home
from bulbi.secrets.model import ResolvedSecret
from bulbi.spec import SecretTarget

SECRET_FILE_MODE = 0o600


def box_path(path: str) -> str:
    """A secret file path in the box, with ``~`` meaning the box user's home."""
    return expand_home(path, CONTAINER_HOME)


class SecretDelivery(ABC):
    """Puts resolved secrets where the box expects them."""

    @abstractmethod
    def to_files(self, secret: ResolvedSecret, container: ContainerHandle) -> None:
        """Deliver at box start and on every attach (no-op for per-session kinds)."""

    @abstractmethod
    def to_session(self, secret: ResolvedSecret) -> Mapping[str, str]:
        """Environment entries for one session (empty for file kinds)."""


class EnvDelivery(SecretDelivery):
    """An environment variable named after the secret, set per ``docker exec`` session."""

    def to_files(self, secret: ResolvedSecret, container: ContainerHandle) -> None:
        return

    def to_session(self, secret: ResolvedSecret) -> Mapping[str, str]:
        return {secret.declaration.name: secret.value}


class FileDelivery(SecretDelivery):
    """A mode-600 file owned by the box user, rewritten atomically on every attach."""

    def to_files(self, secret: ResolvedSecret, container: ContainerHandle) -> None:
        path = secret.declaration.path
        if not path:
            raise SandboxError(f"secret {secret.declaration.name} has no path")
        container.write_file(box_path(path), secret.value, mode=SECRET_FILE_MODE)

    def to_session(self, secret: ResolvedSecret) -> Mapping[str, str]:
        return {}


class SecretDeliveries:
    """The delivery for each ``to`` kind."""

    def __init__(self, deliveries: Mapping[SecretTarget, SecretDelivery]) -> None:
        self._deliveries = dict(deliveries)

    @classmethod
    def builtin(cls) -> SecretDeliveries:
        return cls({SecretTarget.ENV: EnvDelivery(), SecretTarget.FILE: FileDelivery()})

    def write_files(self, secrets: Iterable[ResolvedSecret], container: ContainerHandle) -> None:
        for secret in secrets:
            self._deliveries[secret.declaration.target].to_files(secret, container)

    def session_environment(self, secrets: Iterable[ResolvedSecret]) -> dict[str, str]:
        environment: dict[str, str] = {}
        for secret in secrets:
            environment.update(self._deliveries[secret.declaration.target].to_session(secret))
        return environment
