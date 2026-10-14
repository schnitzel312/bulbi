"""Auto-detect project type and generate a starter bulbi.toml spec."""

from __future__ import annotations

import json
from pathlib import Path

from bulbi.agents import get_agent_config


# Domain allowlists per ecosystem.
_REGISTRY_DOMAINS: dict[str, list[str]] = {
    "python": ["pypi.org", "files.pythonhosted.org"],
    "node": ["registry.npmjs.org", "registry.yarnpkg.com"],
    "rust": ["crates.io", "static.crates.io"],
    "go": ["proxy.golang.org", "sum.golang.org"],
}


def _detect_project(project_root: Path) -> dict:
    """Detect the project type and return metadata used to build the spec.

    Returns a dict with keys:
        name, lang, tools, network_allow
    """
    name = project_root.resolve().name
    tools: list[str] = []
    lang: str | None = None
    network_allow: list[str] = []

    # --- Python -----------------------------------------------------------
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        lang = "python"
        tools = ["python", "git", "rg"]
        network_allow = list(_REGISTRY_DOMAINS["python"])

        # Try to read the project name from pyproject.toml.
        try:
            import tomllib

            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
            name = (
                data.get("project", {}).get("name")
                or data.get("tool", {}).get("poetry", {}).get("name")
                or name
            )
        except Exception:
            pass

        if (project_root / "poetry.lock").exists():
            tools.append("poetry")
        if (project_root / "uv.lock").exists():
            tools.append("uv")

        return {"name": name, "lang": lang, "tools": tools, "network_allow": network_allow}

    # --- Node / JavaScript ------------------------------------------------
    pkg_json = project_root / "package.json"
    if pkg_json.exists():
        lang = "node"
        tools = ["node", "git", "rg"]
        network_allow = list(_REGISTRY_DOMAINS["node"])

        try:
            data = json.loads(pkg_json.read_text())
            name = data.get("name", name)
        except Exception:
            pass

        if (project_root / "pnpm-lock.yaml").exists():
            tools.append("pnpm")
        if (project_root / "yarn.lock").exists():
            tools.append("yarn")

        return {"name": name, "lang": lang, "tools": tools, "network_allow": network_allow}

    # --- Rust -------------------------------------------------------------
    if (project_root / "Cargo.toml").exists():
        lang = "rust"
        tools = ["rust", "cargo", "git", "rg"]
        network_allow = list(_REGISTRY_DOMAINS["rust"])

        try:
            import tomllib

            with open(project_root / "Cargo.toml", "rb") as f:
                data = tomllib.load(f)
            name = data.get("package", {}).get("name", name)
        except Exception:
            pass

        return {"name": name, "lang": lang, "tools": tools, "network_allow": network_allow}

    # --- Go ---------------------------------------------------------------
    if (project_root / "go.mod").exists():
        lang = "go"
        tools = ["go", "git", "rg"]
        network_allow = list(_REGISTRY_DOMAINS["go"])
        return {"name": name, "lang": lang, "tools": tools, "network_allow": network_allow}

    # --- Fallback ---------------------------------------------------------
    tools = ["git", "rg"]
    return {"name": name, "lang": None, "tools": tools, "network_allow": network_allow}


def generate_starter_spec(project_root: Path) -> str:
    """Return a TOML string for a starter ``bulbi.toml``.

    The spec is tailored to the detected project type and includes inline
    comments explaining each section.
    """
    info = _detect_project(project_root)

    tools_list = ", ".join(f'"{t}"' for t in info["tools"])
    # Combine ecosystem registry domains with agent-required domains.
    agent_config = get_agent_config("claude")
    agent_domains = agent_config.domains if agent_config else []
    all_domains = list(info["network_allow"]) + agent_domains
    network_allow = ", ".join(f'"{d}"' for d in all_domains)

    lang_comment = f"  # Detected: {info['lang']} project" if info["lang"] else "  # No specific language detected"

    lines = [
        '# Bulbi spec — defines the sandbox environment for coding agents.',
        '# Docs: https://github.com/anthropics/bulbi',
        '',
        '# Spec format version (do not change).',
        'spec = "0.1"',
        '',
        '# ---- Box identity ---------------------------------------------------',
        '[box]',
        f'name = "{info["name"]}"',
        'agent = "claude"',
        '',
        '# ---- Tools installed in the container --------------------------------',
        '[tools]',
        f'allow = [{tools_list}]{lang_comment}',
        '',
        '# ---- Setup commands run once when the image is built -----------------',
        '[setup]',
        'run = []',
        '',
        '# ---- Filesystem mounts ----------------------------------------------',
        '# Mount the project directory read-write, excluding secrets.',
        '[[mount]]',
        'path = "."',
        'mode = "read-write"',
        'exclude = [".env", "*.pem", "*.key"]',
        '',
        '# ---- Network access -------------------------------------------------',
        '# Default deny: only the domains listed below are reachable.',
        '[network]',
        'default = "deny"',
        f'allow = [{network_allow}]',
        '',
        '# ---- Resource limits ------------------------------------------------',
        '[limits]',
        'cpu = 2',
        'memory = "4GB"',
        '',
        '# ---- Profiles (optional) --------------------------------------------',
        '# Profiles narrow the root spec. Uncomment to define a read-only profile.',
        '# [profiles.readonly]',
        '# [profiles.readonly.mounts]',
        '# "." = "read-only"',
        '',
    ]

    return "\n".join(lines)
