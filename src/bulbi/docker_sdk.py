"""Lazy access to the Docker SDK.

Importing ``docker`` is comparatively slow, and ``bulbi init``, ``check`` and ``log``
never need it, so it is only imported when a Docker operation actually runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from bulbi.errors import SandboxError


def docker_sdk() -> Any:
    """The ``docker`` package (untyped), with its ``errors`` and ``types`` submodules loaded."""
    import docker  # noqa: PLC0415 - deliberately lazy, see module docstring
    import docker.errors  # noqa: PLC0415
    import docker.types  # noqa: PLC0415

    return docker


def connect_to_docker() -> Any:
    """A client for the Docker daemon configured in the environment.

    Connection failures raise the SDK's own errors; the caller (``AppContext``) wraps
    them, which also covers injected client factories.
    """
    return docker_sdk().from_env()


@contextmanager
def docker_errors(action: str) -> Iterator[None]:
    """Re-raise Docker SDK failures as :class:`SandboxError` prefixed with ``action``."""
    try:
        yield
    except docker_sdk().errors.DockerException as exc:
        raise SandboxError(f"{action}: {exc}") from exc
