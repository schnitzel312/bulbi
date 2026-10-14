"""Building (or reusing) a box's Docker image."""

from __future__ import annotations

import hashlib
import io
from typing import Any

from bulbi.agents import Agent
from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_VALUE
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.image.dockerfile import DockerfileBuilder
from bulbi.spec import BulbiSpec

_TAG_HASH_LENGTH = 16


class ImageBuilder:
    """Builds images through an injected Docker client, reusing any image already tagged.

    The tag embeds a hash of the rendered Dockerfile, so an image is rebuilt exactly when
    its recipe changes.
    """

    def __init__(self, docker_client: Any, dockerfile: DockerfileBuilder) -> None:
        self._docker = docker_client
        self._dockerfile = dockerfile

    def tag_for(self, spec: BulbiSpec, agent: Agent) -> str:
        """``bulbi/<box name>:<hash of the Dockerfile>``."""
        dockerfile = self._dockerfile.build(spec, agent)
        digest = hashlib.sha256(dockerfile.encode()).hexdigest()[:_TAG_HASH_LENGTH]
        return f"bulbi/{spec.box.name}:{digest}"

    def build(self, spec: BulbiSpec, agent: Agent) -> str:
        """Ensure the image for ``spec`` exists and return its tag."""
        tag = self.tag_for(spec, agent)
        if self._exists(tag):
            return tag
        dockerfile = self._dockerfile.build(spec, agent)
        with docker_errors(f"failed to build image {tag}"):
            self._docker.images.build(
                fileobj=io.BytesIO(dockerfile.encode()),
                tag=tag,
                labels={DOCKER_LABEL: DOCKER_LABEL_VALUE},
                rm=True,
            )
        return tag

    def _exists(self, tag: str) -> bool:
        with docker_errors(f"failed to look up image {tag}"):
            try:
                self._docker.images.get(tag)
            except docker_sdk().errors.ImageNotFound:
                return False
        return True
