"""Building the gateway image from Bulbi's own (standard-library only) gateway code."""

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from typing import Any

import bulbi
from bulbi.constants import DOCKER_LABEL, DOCKER_LABEL_VALUE
from bulbi.docker_sdk import docker_errors, docker_sdk
from bulbi.gateway.config import RESOLVER_UID

GATEWAY_REPOSITORY = "bulbi/gateway"
_TAG_HASH_LENGTH = 16
_IMAGE_SOURCE_ROOT = "/opt/bulbi"

# Only these modules go into the image; none of them may import Docker, Click or Rich.
_PACKAGE_FILES = ("__init__.py", "constants.py", "errors.py")
_GATEWAY_PACKAGE = "gateway"

DOCKERFILE = f"""\
FROM debian:bookworm-slim
RUN apt-get update && \\
    apt-get install -y --no-install-recommends nftables python3 && \\
    rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid {RESOLVER_UID} --no-create-home --shell /usr/sbin/nologin bulbi-dns
COPY bulbi {_IMAGE_SOURCE_ROOT}/bulbi
ENV PYTHONPATH={_IMAGE_SOURCE_ROOT} PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-m", "bulbi.gateway.daemon"]
"""


class GatewayImageBuilder:
    """Builds ``bulbi/gateway:<content hash>`` once per version of the gateway code."""

    def __init__(self, docker_client: Any, package_root: Path | None = None) -> None:
        self._docker = docker_client
        self._package_root = package_root or Path(bulbi.__file__).parent

    def build_context(self) -> dict[str, bytes]:
        """Archive path -> content for the Dockerfile and every gateway source file."""
        files = {"Dockerfile": DOCKERFILE.encode()}
        for name in _PACKAGE_FILES:
            files[f"bulbi/{name}"] = (self._package_root / name).read_bytes()
        for source in sorted((self._package_root / _GATEWAY_PACKAGE).glob("*.py")):
            files[f"bulbi/{_GATEWAY_PACKAGE}/{source.name}"] = source.read_bytes()
        return files

    def tag(self, context: dict[str, bytes] | None = None) -> str:
        digest = hashlib.sha256()
        for path, content in sorted((context or self.build_context()).items()):
            digest.update(path.encode() + b"\0" + content + b"\0")
        return f"{GATEWAY_REPOSITORY}:{digest.hexdigest()[:_TAG_HASH_LENGTH]}"

    def build(self) -> str:
        """Ensure the gateway image exists and return its tag."""
        context = self.build_context()
        tag = self.tag(context)
        with docker_errors(f"failed to look up image {tag}"):
            try:
                self._docker.images.get(tag)
                return tag
            except docker_sdk().errors.ImageNotFound:
                pass
        with docker_errors(f"failed to build image {tag}"):
            self._docker.images.build(
                fileobj=_tar(context),
                custom_context=True,
                tag=tag,
                labels={DOCKER_LABEL: DOCKER_LABEL_VALUE},
                rm=True,
            )
        return tag


def _tar(files: dict[str, bytes]) -> io.BytesIO:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    buffer.seek(0)
    return buffer
