"""Counting a box's active sessions from Docker itself (spec §8.3).

Each session is a ``docker exec`` of the entrypoint, so a session that crashes or whose
terminal is killed stops counting by itself. Bulbi's own setup execs (agent prepare,
health checks) run other programs directly and are never counted. (Docker's exec
inspection does not expose an exec's environment, so sessions are recognised by their
entrypoint; they also carry ``BULBI_EXEC=session`` for the in-box idle watcher.)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from bulbi.constants import ENTRYPOINT_PATH
from bulbi.docker_sdk import docker_errors, docker_sdk


class SessionTracker(ABC):
    """Knows how many sessions are running in a box."""

    @abstractmethod
    def active_sessions(self, container_id: str) -> int:
        """Running sessions in the container; 0 if it is gone or stopped."""


class DockerSessionTracker(SessionTracker):
    """Inspects the container's exec instances."""

    def __init__(self, docker_client: Any) -> None:
        self._docker = docker_client

    def active_sessions(self, container_id: str) -> int:
        with docker_errors(f"failed to inspect sessions of {container_id}"):
            try:
                container = self._docker.containers.get(container_id)
            except docker_sdk().errors.NotFound:
                return 0
            exec_ids = container.attrs.get("ExecIDs") or []
            return sum(1 for exec_id in exec_ids if self._is_running_session(exec_id))

    def _is_running_session(self, exec_id: str) -> bool:
        try:
            info = self._docker.api.exec_inspect(exec_id)
        except docker_sdk().errors.NotFound:
            return False
        process = info.get("ProcessConfig") or {}
        return bool(info.get("Running")) and process.get("entrypoint") == ENTRYPOINT_PATH
