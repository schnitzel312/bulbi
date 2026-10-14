"""Docker volumes holding isolated-mode box repositories (one per project)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_ROLE, DOCKER_LABEL_VALUE
from bulbi.docker_sdk import docker_errors, docker_sdk

BOX_REPO_ROLE = "git-repo"


class GitVolumeManager:
    """Creates the volume a box repository lives in; never removes one (it may hold
    commits that were not pulled yet)."""

    def __init__(self, docker_client: Any) -> None:
        self._docker = docker_client

    def exists(self, name: str) -> bool:
        with docker_errors(f"failed to inspect volume {name}"):
            try:
                self._docker.volumes.get(name)
            except docker_sdk().errors.NotFound:
                return False
            return True

    def ensure(self, name: str, labels: Mapping[str, str]) -> None:
        """Create the volume unless it exists; an existing one is never replaced."""
        if self.exists(name):
            return
        with docker_errors(f"failed to create volume {name}"):
            self._docker.volumes.create(
                name=name,
                labels={
                    **labels,
                    DOCKER_LABEL: DOCKER_LABEL_VALUE,
                    DOCKER_LABEL_ROLE: BOX_REPO_ROLE,
                },
            )
