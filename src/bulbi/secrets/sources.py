"""Reading secret values on the host, one reader per ``from`` kind (spec §10.1).

To support a new source, subclass :class:`SecretReader` and register it in
:meth:`SecretReaders.builtin`.
"""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from pathlib import Path

from bulbi.constants import MACOS_SYSTEM_NAME
from bulbi.spec import SecretSource

COMMAND_TIMEOUT_SECONDS = 10
_KEYCHAIN_TIMEOUT_SECONDS = 5

CommandRunner = Callable[..., "subprocess.CompletedProcess[str]"]


class SecretUnavailableError(Exception):
    """A secret could not be read; the message names the cause, never a value."""


class SecretReader(ABC):
    """Reads one kind of secret source on the host."""

    @abstractmethod
    def read(self, source: str) -> str:
        """The value for ``source``; raise :class:`SecretUnavailableError` if there is none."""


class EnvReader(SecretReader):
    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = os.environ if environ is None else environ

    def read(self, source: str) -> str:
        value = self._environ.get(source)
        if not value:
            raise SecretUnavailableError(f"environment variable {source} is not set")
        return value


class FileReader(SecretReader):
    def __init__(self, home: Path | None = None) -> None:
        self._home = home

    def read(self, source: str) -> str:
        home = self._home or Path.home()
        path = Path(source.replace("~", str(home), 1) if source.startswith("~") else source)
        try:
            return path.read_text()
        except OSError as exc:
            raise SecretUnavailableError(f"cannot read {source}: {exc.strerror}") from None


class KeychainReader(SecretReader):
    """macOS Keychain generic passwords (``security find-generic-password -s <service> -w``)."""

    def __init__(self, runner: CommandRunner = subprocess.run, system: str | None = None) -> None:
        self._run = runner
        self._system = system

    def read(self, source: str) -> str:
        if (self._system or platform.system()) != MACOS_SYSTEM_NAME:
            raise SecretUnavailableError("the keychain is only available on macOS")
        argv = ["security", "find-generic-password", "-s", source, "-w"]
        try:
            result = self._run(
                argv, capture_output=True, text=True, timeout=_KEYCHAIN_TIMEOUT_SECONDS
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecretUnavailableError(
                f"keychain lookup for {source} failed: {type(exc).__name__}"
            ) from None
        value = result.stdout.strip()
        if result.returncode != 0 or not value:
            raise SecretUnavailableError(f"no keychain item {source}")
        return value


class CommandReader(SecretReader):
    """Runs the command on the host (argv split, no shell, 10 s timeout); stdout trimmed."""

    def __init__(
        self, runner: CommandRunner = subprocess.run, timeout: float = COMMAND_TIMEOUT_SECONDS
    ) -> None:
        self._run = runner
        self._timeout = timeout

    def read(self, source: str) -> str:
        try:
            argv = shlex.split(source)
        except ValueError as exc:
            raise SecretUnavailableError(f"cannot parse command: {exc}") from None
        if not argv:
            raise SecretUnavailableError("empty command")
        try:
            result = self._run(argv, capture_output=True, text=True, timeout=self._timeout)
        except subprocess.TimeoutExpired:
            raise SecretUnavailableError(
                f"`{argv[0]}` timed out after {self._timeout:g}s"
            ) from None
        except OSError as exc:
            raise SecretUnavailableError(f"`{argv[0]}` could not run: {exc.strerror}") from None
        value = result.stdout.strip()
        if result.returncode != 0:
            # stderr may echo the secret or parts of it, so it is never repeated here.
            raise SecretUnavailableError(f"`{argv[0]}` exited with status {result.returncode}")
        if not value:
            raise SecretUnavailableError(f"`{argv[0]}` printed nothing")
        return value


class SecretReaders:
    """The reader for each ``from`` kind."""

    def __init__(self, readers: Mapping[SecretSource, SecretReader]) -> None:
        self._readers = dict(readers)

    @classmethod
    def builtin(cls) -> SecretReaders:
        return cls(
            {
                SecretSource.ENV: EnvReader(),
                SecretSource.FILE: FileReader(),
                SecretSource.KEYCHAIN: KeychainReader(),
                SecretSource.COMMAND: CommandReader(),
            }
        )

    def read(self, kind: SecretSource, source: str) -> str:
        reader = self._readers.get(kind)
        if reader is None:
            raise SecretUnavailableError(f"no reader for '{kind}' secrets")
        return reader.read(source)
