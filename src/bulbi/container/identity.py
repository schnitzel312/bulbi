"""Which box serves a project (spec §8.1): names and labels derived from the box key."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from bulbi.constants import (
    DOCKER_LABEL,
    DOCKER_LABEL_BOX,
    DOCKER_LABEL_PROFILE,
    DOCKER_LABEL_PROJECT,
    DOCKER_LABEL_ROLE,
    DOCKER_LABEL_SPEC_HASH,
    DOCKER_LABEL_VALUE,
    GATEWAY_ROLE,
)

_HASH_LENGTH = 8
_UNSAFE_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_.-]")
GATEWAY_SUFFIX = "-gw"
NETWORK_SUFFIX = "-net"


@dataclass(frozen=True)
class BoxIdentity:
    """The box key: the project (git common dir or folder) plus the profile."""

    project: Path
    box_name: str
    profile: str | None = None

    @property
    def name(self) -> str:
        project_hash = hashlib.sha256(str(self.project).encode()).hexdigest()[:_HASH_LENGTH]
        name = f"bulbi-{self.box_name}-{project_hash}"
        if self.profile:
            name += f"-{_UNSAFE_NAME_CHARS.sub('_', self.profile)}"
        return name

    @property
    def gateway_name(self) -> str:
        return self.name + GATEWAY_SUFFIX

    @property
    def network_name(self) -> str:
        return self.name + NETWORK_SUFFIX

    def labels(self, spec_hash: str | None = None, *, gateway: bool = False) -> dict[str, str]:
        labels = {
            DOCKER_LABEL: DOCKER_LABEL_VALUE,
            DOCKER_LABEL_BOX: self.box_name,
            DOCKER_LABEL_PROJECT: str(self.project),
            DOCKER_LABEL_PROFILE: self.profile or "",
        }
        if spec_hash is not None:
            labels[DOCKER_LABEL_SPEC_HASH] = spec_hash
        if gateway:
            labels[DOCKER_LABEL_ROLE] = GATEWAY_ROLE
        return labels
