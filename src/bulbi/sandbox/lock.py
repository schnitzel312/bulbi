"""Serialising box start-up between terminals (spec §8.2)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_FILENAME = "box.lock"


class BoxLock(ABC):
    """An exclusive lock around inspecting and changing a project's box."""

    @abstractmethod
    @contextmanager
    def hold(self) -> Iterator[None]:
        """Block until the lock is ours; release it on exit."""


class FileBoxLock(BoxLock):
    """``fcntl.flock`` on ``.bulbi/box.lock``: released by the kernel if the CLI dies."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @contextmanager
    def hold(self) -> Iterator[None]:
        import fcntl  # noqa: PLC0415 - POSIX only; imported where it is used

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
