"""Built-in tool definitions targeting ``debian:bookworm-slim``.

To add a tool, append a :class:`ToolDefinition` to :data:`BUILTIN_TOOLS`.
"""

from __future__ import annotations

from bulbi.tools.models import ToolDefinition

# Minimal utilities installed in every box, whatever the spec allows.
BASE_PACKAGES: tuple[str, ...] = ("bash", "coreutils", "ca-certificates", "less")

BUILTIN_TOOLS: tuple[ToolDefinition, ...] = (
    # The pinned python/node version is advisory: see the TODO(bulbi) on AptInstaller.
    ToolDefinition(
        name="python",
        packages=("python3", "python3-full", "python3-venv", "python3-pip"),
        post_install=("ln -sf /usr/bin/python3 /usr/local/bin/python",),
        verify_cmd="python --version",
        default_version="3.12",
        allowed_versions=("3.10", "3.11", "3.12", "3.13"),
    ),
    ToolDefinition(
        name="node",
        packages=("nodejs", "npm"),
        verify_cmd="node --version",
        default_version="20",
        allowed_versions=("18", "20", "22"),
    ),
    ToolDefinition(
        name="poetry",
        packages=("pipx",),
        post_install=(
            "pipx install poetry",
            "ln -sf ~/.local/bin/poetry /usr/local/bin/poetry",
        ),
        verify_cmd="poetry --version",
    ),
    ToolDefinition(
        name="uv",
        packages=("curl",),
        post_install=(
            "curl -LsSf https://astral.sh/uv/install.sh | sh",
            "ln -sf ~/.local/bin/uv /usr/local/bin/uv",
        ),
        verify_cmd="uv --version",
    ),
    ToolDefinition(name="git", packages=("git",), verify_cmd="git --version"),
    ToolDefinition(name="rg", packages=("ripgrep",), verify_cmd="rg --version"),
    ToolDefinition(
        name="fd",
        packages=("fd-find",),
        post_install=("ln -sf /usr/bin/fdfind /usr/local/bin/fd",),
        verify_cmd="fd --version",
    ),
    ToolDefinition(name="jq", packages=("jq",), verify_cmd="jq --version"),
    ToolDefinition(name="curl", packages=("curl",), verify_cmd="curl --version"),
    ToolDefinition(name="make", packages=("make",), verify_cmd="make --version"),
    ToolDefinition(
        name="gcc", packages=("gcc", "g++", "libc6-dev"), verify_cmd="gcc --version"
    ),
    ToolDefinition(
        name="go", packages=("golang",), verify_cmd="go version", default_version="1.22"
    ),
    ToolDefinition(
        name="rust",
        packages=("curl", "build-essential"),
        post_install=(
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
            "ln -sf ~/.cargo/bin/* /usr/local/bin/",
        ),
        verify_cmd="rustc --version",
    ),
    # Installed by the rust toolchain; listed so specs can name it explicitly.
    ToolDefinition(name="cargo", packages=(), verify_cmd="cargo --version"),
    ToolDefinition(
        name="pnpm",
        packages=("npm",),
        post_install=("npm install -g pnpm",),
        verify_cmd="pnpm --version",
    ),
    ToolDefinition(
        name="yarn",
        packages=("npm",),
        post_install=("npm install -g yarn",),
        verify_cmd="yarn --version",
    ),
    ToolDefinition(
        name="bun",
        packages=("curl", "unzip"),
        post_install=(
            "curl -fsSL https://bun.sh/install | bash",
            "ln -sf ~/.bun/bin/bun /usr/local/bin/bun",
        ),
        verify_cmd="bun --version",
    ),
)
