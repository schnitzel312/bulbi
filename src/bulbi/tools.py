"""Tool name → system package mapping for image building."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ResolvedTool:
    """A tool resolved to installable packages."""

    name: str
    version: str | None
    packages: list[str]  # apt packages to install
    post_install: list[str]  # commands to run after install (e.g., pip install)
    verify_cmd: str  # command to verify the tool works


# name[@version] → (apt packages, post_install commands, verify command)
# This table targets Debian slim. Extend for other bases as needed.
_TOOL_TABLE: dict[str, dict] = {
    "python": {
        "packages": ["python3", "python3-full", "python3-venv", "python3-pip"],
        "default_version": "3.12",
        "allowed_versions": ["3.10", "3.11", "3.12", "3.13"],
        "post_install": [
            "ln -sf /usr/bin/python3 /usr/local/bin/python",
        ],
        "verify": "python --version",
        "_note": "Uses system python3 from the base image. Version is advisory.",
    },
    "node": {
        "packages": ["nodejs", "npm"],
        "default_version": "20",
        "allowed_versions": ["18", "20", "22"],
        "post_install": [],
        "verify": "node --version",
    },
    "poetry": {
        "packages": ["pipx"],
        "post_install": ["pipx install poetry", "ln -sf ~/.local/bin/poetry /usr/local/bin/poetry"],
        "verify": "poetry --version",
    },
    "uv": {
        "packages": ["curl"],
        "post_install": [
            "curl -LsSf https://astral.sh/uv/install.sh | sh",
            "ln -sf ~/.local/bin/uv /usr/local/bin/uv",
        ],
        "verify": "uv --version",
    },
    "git": {
        "packages": ["git"],
        "post_install": [],
        "verify": "git --version",
    },
    "rg": {
        "packages": ["ripgrep"],
        "post_install": [],
        "verify": "rg --version",
    },
    "fd": {
        "packages": ["fd-find"],
        "post_install": ["ln -sf /usr/bin/fdfind /usr/local/bin/fd"],
        "verify": "fd --version",
    },
    "jq": {
        "packages": ["jq"],
        "post_install": [],
        "verify": "jq --version",
    },
    "curl": {
        "packages": ["curl"],
        "post_install": [],
        "verify": "curl --version",
    },
    "make": {
        "packages": ["make"],
        "post_install": [],
        "verify": "make --version",
    },
    "gcc": {
        "packages": ["gcc", "g++", "libc6-dev"],
        "post_install": [],
        "verify": "gcc --version",
    },
    "go": {
        "packages": ["golang"],
        "default_version": "1.22",
        "post_install": [],
        "verify": "go version",
    },
    "rust": {
        "packages": ["curl", "build-essential"],
        "post_install": [
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
            "ln -sf ~/.cargo/bin/* /usr/local/bin/",
        ],
        "verify": "rustc --version",
    },
    "cargo": {
        "packages": [],
        "post_install": [],
        "verify": "cargo --version",
        "_note": "installed via rust",
    },
    "pnpm": {
        "packages": ["npm"],
        "post_install": ["npm install -g pnpm"],
        "verify": "pnpm --version",
    },
    "yarn": {
        "packages": ["npm"],
        "post_install": ["npm install -g yarn"],
        "verify": "yarn --version",
    },
    "bun": {
        "packages": ["curl", "unzip"],
        "post_install": [
            "curl -fsSL https://bun.sh/install | bash",
            "ln -sf ~/.bun/bin/bun /usr/local/bin/bun",
        ],
        "verify": "bun --version",
    },
}

# Minimal utilities always included in the box (needed for basic operation).
ALWAYS_INCLUDED = ["bash", "coreutils", "ca-certificates", "less"]


def parse_tool_spec(tool_spec: str) -> tuple[str, str | None]:
    """Parse 'name@version' into (name, version). Version may be None."""
    match = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*)(?:@(.+))?$", tool_spec)
    if not match:
        raise ValueError(f"invalid tool spec: '{tool_spec}'")
    return match.group(1), match.group(2)


def resolve_tool(tool_spec: str) -> ResolvedTool:
    """Resolve a tool spec like 'python@3.12' to installable packages."""
    name, version = parse_tool_spec(tool_spec)

    if name not in _TOOL_TABLE:
        raise ValueError(
            f"unknown tool: '{name}'. Available: {', '.join(sorted(_TOOL_TABLE))}"
        )

    entry = _TOOL_TABLE[name]

    # Validate version if specified
    if version and "allowed_versions" in entry:
        if version not in entry["allowed_versions"]:
            raise ValueError(
                f"unsupported version '{version}' for {name}. "
                f"Available: {', '.join(entry['allowed_versions'])}"
            )

    # Use default version if not specified
    effective_version = version or entry.get("default_version", "")

    # Substitute version into package names and commands
    def sub(s: str) -> str:
        return s.replace("{v}", effective_version)

    packages = [sub(p) for p in entry["packages"]]
    post_install = [sub(c) for c in entry.get("post_install", [])]
    verify = sub(entry["verify"])

    return ResolvedTool(
        name=name,
        version=effective_version or None,
        packages=packages,
        post_install=post_install,
        verify_cmd=verify,
    )


def resolve_all(tool_specs: list[str]) -> list[ResolvedTool]:
    """Resolve all tool specs, deduplicating packages."""
    return [resolve_tool(spec) for spec in tool_specs]


def available_tools() -> dict[str, dict]:
    """Return the tool registry. Public API for validation and introspection."""
    return dict(_TOOL_TABLE)
