"""Reading agent credentials stored on the host."""

from __future__ import annotations

import json
import platform
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Callable

from bulbi.constants import MACOS_SYSTEM_NAME

_KEYCHAIN_TIMEOUT_SECONDS = 5

CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]


class CredentialProvider(ABC):
    """Source of a credentials JSON document for an agent."""

    @abstractmethod
    def read(self) -> str | None:
        """Return the credentials JSON, or ``None`` if none are available."""


class NoCredentialProvider(CredentialProvider):
    """Used where the host has no credential store Bulbi can read."""

    def read(self) -> str | None:
        return None


class KeychainCredentialProvider(CredentialProvider):
    """Reads a generic password holding JSON from the macOS Keychain."""

    def __init__(self, service: str, runner: CommandRunner = subprocess.run) -> None:
        self._service = service
        self._run = runner

    def read(self) -> str | None:
        try:
            result = self._run(
                ["security", "find-generic-password", "-s", self._service, "-w"],
                capture_output=True,
                text=True,
                timeout=_KEYCHAIN_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        credentials = result.stdout.strip()
        return credentials if _is_json(credentials) else None

    @classmethod
    def for_host(cls, service: str, system: str | None = None) -> CredentialProvider:
        """A Keychain provider on macOS, otherwise a provider that finds nothing."""
        if (system or platform.system()) == MACOS_SYSTEM_NAME:
            return cls(service)
        return NoCredentialProvider()


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return False
    return True
