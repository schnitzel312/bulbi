"""Docker image builder for Bulbi boxes."""

from __future__ import annotations

import base64
import io
from pathlib import Path

import docker

from bulbi.agents import get_agent_config
from bulbi.constants import CONTAINER_HOME, CONTAINER_USER, CONTAINER_WORKSPACE, DOCKER_LABEL
from bulbi.spec import BulbiSpec
from bulbi.tools import ALWAYS_INCLUDED, resolve_all, resolve_tool


def generate_dockerfile(spec: BulbiSpec) -> str:
    """Generate a Dockerfile from a BulbiSpec.

    The image installs resolved tool packages, the configured agent runtime,
    then creates a non-root user. Setup commands that need the project files
    (e.g. `poetry install`) are deferred to an entrypoint script that runs
    at container start, since the project is bind-mounted at runtime.
    """
    resolved = resolve_all(spec.tools.allow)
    agent_config = get_agent_config(spec.box.agent)

    # Collect all apt packages (deduplicated, stable order).
    seen: set[str] = set()
    packages: list[str] = []
    for pkg in ALWAYS_INCLUDED:
        if pkg not in seen:
            seen.add(pkg)
            packages.append(pkg)
    for tool in resolved:
        for pkg in tool.packages:
            if pkg not in seen:
                seen.add(pkg)
                packages.append(pkg)

    # The agent may need additional system packages (e.g. node for claude).
    if agent_config:
        for dep_name in agent_config.requires:
            already_have = any(t.name == dep_name for t in resolved)
            if not already_have:
                dep_tool = resolve_tool(dep_name)
                for pkg in dep_tool.packages:
                    if pkg not in seen:
                        seen.add(pkg)
                        packages.append(pkg)

    lines: list[str] = []
    lines.append("FROM debian:bookworm-slim")
    lines.append("")

    # Install apt packages.
    lines.append("RUN apt-get update && \\")
    lines.append(f"    apt-get install -y --no-install-recommends {' '.join(packages)} && \\")
    lines.append("    rm -rf /var/lib/apt/lists/*")
    lines.append("")

    # Post-install commands per tool.
    for tool in resolved:
        if tool.post_install:
            cmds = " && \\\n    ".join(tool.post_install)
            lines.append(f"# post-install: {tool.name}")
            lines.append(f"RUN {cmds}")
            lines.append("")

    # Install the agent runtime.
    if agent_config:
        for dep_name in agent_config.requires:
            already_have = any(t.name == dep_name for t in resolved)
            if not already_have:
                dep_tool = resolve_tool(dep_name)
                if dep_tool.post_install:
                    cmds = " && \\\n    ".join(dep_tool.post_install)
                    lines.append(f"# post-install: {dep_name} (agent dependency)")
                    lines.append(f"RUN {cmds}")
                    lines.append("")

        lines.append(f"# Install agent: {spec.box.agent}")
        for cmd in agent_config.install_cmds:
            lines.append(f"RUN {cmd}")
        lines.append("")

        for key, value in agent_config.env.items():
            lines.append(f"ENV {key}={value}")
        if agent_config.env:
            lines.append("")

    # Create non-root user and configure pip.
    lines.append(f"RUN useradd -m -s /bin/bash {CONTAINER_USER}")
    lines.append("ENV PIP_BREAK_SYSTEM_PACKAGES=1")
    lines.append(f"ENV PATH={CONTAINER_HOME}/.local/bin:$PATH")
    lines.append("")

    # Write the entrypoint script (base64-encoded to avoid Dockerfile escaping).
    entrypoint_content = _build_entrypoint(spec.setup.run)
    encoded = base64.b64encode(entrypoint_content.encode()).decode()
    lines.append(f"RUN echo '{encoded}' | base64 -d > /entrypoint.sh && chmod +x /entrypoint.sh")
    lines.append("")

    # Lock down: remove apt to prevent runtime installs.
    lines.append("# Lock down: remove system package manager")
    lines.append("RUN rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg && \\")
    lines.append("    rm -rf /var/lib/dpkg /var/lib/apt")
    lines.append("")

    lines.append(f"USER {CONTAINER_USER}")
    lines.append(f"WORKDIR {CONTAINER_WORKSPACE}")
    lines.append('ENTRYPOINT ["/entrypoint.sh"]')
    lines.append('CMD ["bash"]')
    lines.append("")

    return "\n".join(lines)


def _build_entrypoint(setup_cmds: list[str]) -> str:
    """Generate the entrypoint shell script content."""
    lines = [
        "#!/bin/bash",
        "set -e",
        "",
        "# Run setup commands on first start (skip if already done).",
        f'MARKER="{CONTAINER_HOME}/.bulbi-setup-done"',
        'if [ ! -f "$MARKER" ]; then',
        f"    cd {CONTAINER_WORKSPACE}",
    ]
    for cmd in setup_cmds:
        lines.append(f"    {cmd}")
    lines.extend([
        '    touch "$MARKER"',
        "fi",
        "",
        '# Execute the requested command.',
        'exec "$@"',
        "",
    ])
    return "\n".join(lines)


def _image_tag(spec: BulbiSpec) -> str:
    return f"bulbi/{spec.box.name}:{spec.content_hash()}"


def image_exists(spec: BulbiSpec) -> bool:
    client = docker.from_env()
    tag = _image_tag(spec)
    try:
        client.images.get(tag)
        return True
    except docker.errors.ImageNotFound:
        return False


def build_image(spec: BulbiSpec, project_root: Path) -> str:
    """Build (or return cached) Docker image for the spec. Returns the image tag."""
    tag = _image_tag(spec)

    if image_exists(spec):
        return tag

    dockerfile_content = generate_dockerfile(spec)

    client = docker.from_env()
    client.images.build(
        fileobj=io.BytesIO(dockerfile_content.encode()),
        tag=tag,
        labels={DOCKER_LABEL: "true"},
        rm=True,
    )

    return tag
