"""Building (or reusing) a box's Docker image."""

from __future__ import annotations

import io
from typing import Any

import docker.errors

from bulbi.agents import Agent
from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_VALUE
from bulbi.errors import SandboxError
from bulbi.image.dockerfile import DockerfileBuilder
from bulbi.spec import BulbiSpec


class ImageBuilder:
    """Builds images through an injected Docker client, reusing any image already tagged.

    The tag embeds :meth:`BulbiSpec.content_hash`, so an image is rebuilt exactly when
    something that goes into it changes.
    """

    def __init__(self, docker_client: Any, dockerfile: DockerfileBuilder) -> None:
        self._docker = docker_client
        self._dockerfile = dockerfile

    @staticmethod
    def tag_for(spec: BulbiSpec) -> str:
        return f"bulbi/{spec.box.name}:{spec.content_hash()}"

    def build(self, spec: BulbiSpec, agent: Agent) -> str:
        """Ensure the image for ``spec`` exists and return its tag."""
        tag = self.tag_for(spec)
        if self._exists(tag):
            return tag
        dockerfile = self._dockerfile.build(spec, agent)
        try:
            self._docker.images.build(
                fileobj=io.BytesIO(dockerfile.encode()),
                tag=tag,
                labels={DOCKER_LABEL: DOCKER_LABEL_VALUE},
                rm=True,
            )
        except docker.errors.DockerException as exc:
            raise SandboxError(f"failed to build image {tag}: {exc}") from exc
        return tag

    def _exists(self, tag: str) -> bool:
        try:
            self._docker.images.get(tag)
        except docker.errors.ImageNotFound:
            return False
        return True
