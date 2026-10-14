"""Docker volumes holding isolated-mode clones, and the one-shot helpers that fill them.

A helper is a short-lived container from the box's image, with no network, that runs
one script as root (it must hand the volume to the box user) with only the
capabilities file ownership needs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from bulbi.agents.ports import ExecResult
from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_ROLE, DOCKER_LABEL_VALUE
from bulbi.container.manager import BoxManager
from bulbi.container.mounts import PlannedMount
from bulbi.docker_sdk import docker_errors, docker_sdk

HELPER_ROLE = "git-helper"
CLONE_ROLE = "git-clone"
HELPER_USER = "root"
HELPER_CAPABILITIES = ("CHOWN", "DAC_OVERRIDE", "FOWNER")
HELPER_TIMEOUT_SECONDS = 600
_HELPER_ARGV0 = "bulbi-git-helper"


class GitVolumeManager:
    """Creates clone volumes and runs helper containers against them."""

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
        """Create the volume unless it exists; an existing clone is never replaced."""
        if self.exists(name):
            return
        with docker_errors(f"failed to create volume {name}"):
            self._docker.volumes.create(
                name=name,
                labels={**labels, DOCKER_LABEL: DOCKER_LABEL_VALUE, DOCKER_LABEL_ROLE: CLONE_ROLE},
            )

    def run_helper(
        self,
        image: str,
        script: str,
        args: Sequence[str],
        mounts: Sequence[PlannedMount],
    ) -> ExecResult:
        """Run ``bash -c script args...`` in a throwaway container; return its outcome."""
        with docker_errors("failed to run the git helper container"):
            container = self._docker.containers.run(
                image,
                command=["bash", "-c", script, _HELPER_ARGV0, *args],
                entrypoint=[],
                user=HELPER_USER,
                detach=True,
                network_mode="none",
                mounts=[BoxManager.to_docker_mount(mount) for mount in mounts],
                cap_drop=["ALL"],
                cap_add=list(HELPER_CAPABILITIES),
                security_opt=["no-new-privileges"],
                labels={DOCKER_LABEL: DOCKER_LABEL_VALUE, DOCKER_LABEL_ROLE: HELPER_ROLE},
            )
            try:
                status = container.wait(timeout=HELPER_TIMEOUT_SECONDS)
                output = container.logs()
            finally:
                container.remove(force=True)
        exit_code = int(status.get("StatusCode", 1)) if isinstance(status, dict) else 1
        text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
        return ExecResult(exit_code, text)
