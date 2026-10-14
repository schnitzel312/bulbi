"""Tests for Dockerfile generation and image building."""

import base64
import re

import docker.errors
import pytest

from bulbi.agents import ClaudeAgent, CodexAgent, NoCredentialProvider, UnmanagedAgent
from bulbi.errors import SandboxError
from bulbi.image import DockerfileBuilder, EntrypointScript, ImageBuilder
from bulbi.spec import BoxSpec, BulbiSpec, SetupSpec, ToolsSpec
from bulbi.tools import ToolRegistry
from tests.fakes import FakeDocker

CLAUDE = ClaudeAgent(credentials=NoCredentialProvider())


def _spec(tools=("python@3.12", "git"), agent="claude", setup=()) -> BulbiSpec:
    return BulbiSpec(
        spec_version="0.1",
        box=BoxSpec(name="demo", agent=agent),
        tools=ToolsSpec(allow=list(tools)),
        setup=SetupSpec(run=list(setup)),
    )


def _dockerfile(spec: BulbiSpec, agent=CLAUDE) -> str:
    return DockerfileBuilder(ToolRegistry.builtin()).build(spec, agent)


def _apt_packages(dockerfile: str) -> list[str]:
    match = re.search(r"--no-install-recommends (.*) && \\", dockerfile)
    assert match
    return match.group(1).split()


def test_dockerfile_starts_from_debian_and_ends_with_runtime_settings():
    lines = _dockerfile(_spec()).splitlines()
    assert lines[0] == "FROM debian:bookworm-slim"
    assert lines[-4:] == [
        "USER bulbi",
        "WORKDIR /home/bulbi/workspace",
        'ENTRYPOINT ["/entrypoint.sh"]',
        'CMD ["bash"]',
    ]


def test_apt_packages_are_base_then_tools_then_agent_deps_without_duplicates():
    packages = _apt_packages(_dockerfile(_spec(tools=["git", "uv", "curl"])))
    assert packages == [
        "bash", "coreutils", "ca-certificates", "less", "git", "curl", "nodejs", "npm"
    ]  # fmt: skip


def test_agent_dependency_not_reinstalled_when_spec_allows_it():
    dockerfile = _dockerfile(_spec(tools=["node"]))
    assert _apt_packages(dockerfile).count("nodejs") == 1
    assert "(agent dependency)" not in dockerfile


def test_tool_post_install_and_agent_install_sections():
    dockerfile = _dockerfile(_spec(tools=["python", "fd"]))
    assert (
        "# post-install: python\nRUN ln -sf /usr/bin/python3 /usr/local/bin/python" in dockerfile
    )
    assert "# Install agent: claude\nRUN npm install -g @anthropic-ai/claude-code" in dockerfile
    assert "ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1" in dockerfile


def test_multi_command_post_install_is_line_continued():
    dockerfile = _dockerfile(_spec(tools=["uv"]))
    assert (
        "RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \\\n"
        "    ln -sf ~/.local/bin/uv /usr/local/bin/uv"
    ) in dockerfile


def test_agent_without_environment_has_no_env_block():
    dockerfile = _dockerfile(_spec(agent="codex"), agent=CodexAgent())
    assert "# Install agent: codex" in dockerfile
    assert "ENV CLAUDE" not in dockerfile


def test_unmanaged_agent_installs_nothing():
    dockerfile = _dockerfile(_spec(tools=["git"], agent="aider"), agent=UnmanagedAgent("aider"))
    assert "Install agent" not in dockerfile
    assert "nodejs" not in dockerfile


def test_apt_is_removed_after_everything_is_installed():
    dockerfile = _dockerfile(_spec())
    assert dockerfile.index("# Lock down") > dockerfile.index("# Install agent")
    assert "rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg" in dockerfile


def test_entrypoint_is_embedded_as_base64():
    dockerfile = _dockerfile(_spec(setup=["poetry install"]))
    encoded = re.search(r"RUN echo '([^']+)' \| base64 -d > /entrypoint.sh", dockerfile)
    assert encoded
    assert (
        base64.b64decode(encoded.group(1)).decode()
        == EntrypointScript(["poetry install"]).render()
    )


def test_entrypoint_runs_setup_once_then_execs_command():
    script = EntrypointScript(["make deps", "make build"]).render()
    assert script.startswith("#!/bin/bash\nset -e\n")
    assert 'MARKER="/home/bulbi/.bulbi-setup-done"' in script
    assert "    cd /home/bulbi/workspace\n    make deps\n    make build\n" in script
    assert script.endswith('exec "$@"\n')


def test_unknown_tool_fails_dockerfile_generation():
    from bulbi.errors import ToolError

    with pytest.raises(ToolError):
        _dockerfile(_spec(tools=["nope"]))


# ---- ImageBuilder -----------------------------------------------------------


def _image_builder(client: FakeDocker) -> ImageBuilder:
    return ImageBuilder(client, DockerfileBuilder(ToolRegistry.builtin()))


def test_image_tag_uses_box_name_and_content_hash():
    spec = _spec()
    assert ImageBuilder.tag_for(spec) == f"bulbi/demo:{spec.content_hash()}"


def test_build_creates_labelled_image_when_missing():
    client = FakeDocker()
    tag = _image_builder(client).build(_spec(), CLAUDE)
    (build,) = client.images.builds
    assert build["tag"] == tag
    assert build["labels"] == {"bulbi": "true"}
    assert build["dockerfile"].startswith("FROM debian:bookworm-slim")


def test_build_reuses_existing_image():
    spec = _spec()
    client = FakeDocker(images={ImageBuilder.tag_for(spec)})
    assert _image_builder(client).build(spec, CLAUDE) == ImageBuilder.tag_for(spec)
    assert client.images.builds == []


def test_build_failure_becomes_sandbox_error():
    client = FakeDocker()

    def failing_build(**kwargs):
        raise docker.errors.BuildError("boom", build_log=[])

    client.images.build = failing_build
    with pytest.raises(SandboxError, match="failed to build image"):
        _image_builder(client).build(_spec(), CLAUDE)


class _PreinstalledAgent(UnmanagedAgent):
    """An agent shipped by one of its required tools: nothing to install itself."""

    required_tools = ("rust",)
    environment = {"PRE_MODE": "1"}  # noqa: RUF012


def test_agent_without_install_commands_keeps_dependencies_and_env():
    dockerfile = _dockerfile(_spec(tools=["git"], agent="pre"), agent=_PreinstalledAgent("pre"))
    assert "# post-install: rust (agent dependency)" in dockerfile
    assert "sh.rustup.rs" in dockerfile
    assert "ENV PRE_MODE=1" in dockerfile
    assert "Install agent" not in dockerfile
