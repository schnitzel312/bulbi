"""Container lifecycle manager for Bulbi boxes."""

from __future__ import annotations

import glob as globmod
import hashlib
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

import docker
import docker.types

from bulbi.agents import Agent, AgentRegistry
from bulbi.constants import (
    CONTAINER_WORKSPACE,
    DOCKER_LABEL,
    DOCKER_LABEL_BOX,
    SPEC_FILENAME,
)
from bulbi.container.execution import DockerContainerExecutor
from bulbi.image import build_image
from bulbi.spec import BulbiSpec, ProfileMerger

_MEMORY_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def _parse_memory(mem: str) -> int:
    """Parse a memory string like '4GB' into bytes."""
    match = re.match(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)$", mem.upper())
    if not match:
        raise ValueError(f"invalid memory string: '{mem}'")
    value = float(match.group(1))
    unit = match.group(2)
    return int(value * _MEMORY_UNITS[unit])


def _proxy_host() -> str:
    if platform.system() == "Darwin":
        return "host.docker.internal"
    return "172.17.0.1"


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _resolve_path(raw: str, project_root: Path) -> Path:
    if raw.startswith("~"):
        return Path(raw).expanduser().resolve()
    p = Path(raw)
    if p.is_absolute():
        return p
    return (project_root / p).resolve()


def _detect_git_worktree(project_root: Path) -> Path | None:
    """If project_root/.git is a worktree file, return the real git dir."""
    dot_git = project_root / ".git"
    if dot_git.is_file():
        text = dot_git.read_text().strip()
        if text.startswith("gitdir:"):
            gitdir = text.split(":", 1)[1].strip()
            resolved = (project_root / gitdir).resolve()
            if "worktrees" in resolved.parts:
                idx = resolved.parts.index("worktrees")
                return Path(*resolved.parts[:idx])
            return resolved
    return None


def _is_tty() -> bool:
    """Check if stdin/stdout are connected to a terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Container lifecycle
# ---------------------------------------------------------------------------

def _build_mounts(
    spec: BulbiSpec,
    project_root: Path,
) -> list[docker.types.Mount]:
    """Build the list of Docker bind mounts from the spec."""
    mounts: list[docker.types.Mount] = []

    for m in spec.mounts:
        host_path = _resolve_path(m.path, project_root)
        if m.path == ".":
            container_path = CONTAINER_WORKSPACE
        else:
            container_path = f"{CONTAINER_WORKSPACE}/{host_path.name}"
        mounts.append(docker.types.Mount(
            target=container_path,
            source=str(host_path),
            type="bind",
            read_only=m.mode == "read-only",
        ))

        # Overlay excludes: mask existing host files with /dev/null.
        for excl in m.exclude:
            for matched_path in globmod.glob(str(host_path / excl)):
                rel = Path(matched_path).relative_to(host_path)
                mounts.append(docker.types.Mount(
                    target=f"{container_path}/{rel}",
                    source="/dev/null",
                    type="bind",
                    read_only=True,
                ))

    # Mount bulbi.toml as read-only.
    spec_path = project_root / SPEC_FILENAME
    if spec_path.exists():
        mounts.append(docker.types.Mount(
            target=f"{CONTAINER_WORKSPACE}/{SPEC_FILENAME}",
            source=str(spec_path),
            type="bind",
            read_only=True,
        ))

    # Git worktree support.
    real_git_dir = _detect_git_worktree(project_root)
    if real_git_dir is not None:
        mounts.append(docker.types.Mount(
            target=f"{CONTAINER_WORKSPACE}/.git-main",
            source=str(real_git_dir),
            type="bind",
            read_only=False,
        ))

    return mounts


def _build_environment(
    spec: BulbiSpec,
    agent: Agent,
    proxy_port: int,
) -> dict[str, str]:
    """Build the container environment dict."""
    proxy = _proxy_host()
    proxy_url = f"http://{proxy}:{proxy_port}"
    env = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
    }

    env.update(agent.environment)
    env.update(agent.api_keys_from(os.environ))

    return env


def start_box(
    spec: BulbiSpec,
    project_root: Path,
    profile: str | None = None,
    proxy_port: int = 8080,
) -> str:
    """Build image and start a long-running container. Returns container ID."""
    if profile is not None:
        spec = ProfileMerger().resolve(spec, profile)

    image_tag = build_image(spec, project_root)
    client = docker.from_env()

    box_name = spec.box.name
    container_name = f"bulbi-{box_name}-{_short_hash(str(project_root))}"

    mounts = _build_mounts(spec, project_root)
    agent = AgentRegistry.builtin().resolve(spec.box.agent)
    env = _build_environment(spec, agent, proxy_port)

    # Remove any stale container with the same name.
    try:
        stale = client.containers.get(container_name)
        stale.remove(force=True)
    except docker.errors.NotFound:
        pass

    container = client.containers.run(
        image_tag,
        command=["sleep", "infinity"],
        entrypoint=[],
        detach=True,
        name=container_name,
        labels={DOCKER_LABEL: "true", DOCKER_LABEL_BOX: box_name},
        mounts=mounts,
        nano_cpus=spec.limits.cpu * 10**9,
        mem_limit=_parse_memory(spec.limits.memory),
        environment=env,
        stdin_open=True,
        tty=True,
    )

    # Inject agent config so it skips onboarding and picks up host auth.
    agent.prepare_container(DockerContainerExecutor(container), env)

    return container.id


def run_in_box(container_id: str, command: list[str]) -> int:
    """Run a command inside the container via `docker exec`.

    Uses subprocess so the Docker CLI handles TTY allocation, signal
    forwarding, and window resizing.
    """
    docker_cmd = ["docker", "exec"]
    if _is_tty():
        docker_cmd.append("-it")
    docker_cmd.extend([container_id, "/entrypoint.sh"] + command)

    result = subprocess.run(docker_cmd)
    return result.returncode


def stop_box(container_id: str) -> None:
    client = docker.from_env()
    try:
        container = client.containers.get(container_id)
        container.stop(timeout=10)
        container.remove()
    except docker.errors.NotFound:
        pass


def list_boxes() -> list[dict]:
    client = docker.from_env()
    containers = client.containers.list(
        all=True,
        filters={"label": f"{DOCKER_LABEL}=true"},
    )
    return [
        {
            "id": c.short_id,
            "name": c.name,
            "status": c.status,
            "box": c.labels.get(DOCKER_LABEL_BOX, ""),
        }
        for c in containers
    ]


def remove_box(container_id: str) -> None:
    client = docker.from_env()
    container = client.containers.get(container_id)
    container.remove(force=True)


def reset_boxes() -> None:
    """Remove all Bulbi containers and images."""
    client = docker.from_env()

    for c in client.containers.list(all=True, filters={"label": f"{DOCKER_LABEL}=true"}):
        c.remove(force=True)

    for img in client.images.list(filters={"label": f"{DOCKER_LABEL}=true"}):
        client.images.remove(img.id, force=True)
