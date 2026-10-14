"""Spec data models and TOML parser for bulbi.toml."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulbi.constants import DEFAULT_CPU, DEFAULT_MEMORY, SPEC_FILENAME, SPEC_VERSION


@dataclass(frozen=True)
class BoxSpec:
    name: str
    agent: str = "claude"


@dataclass(frozen=True)
class ToolsSpec:
    allow: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SetupSpec:
    run: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MountSpec:
    path: str
    mode: str = "read-write"
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in ("read-only", "read-write"):
            raise SpecError(f"mount mode must be 'read-only' or 'read-write', got '{self.mode}'")


@dataclass(frozen=True)
class NetworkSpec:
    default: str = "deny"
    allow: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.default not in ("deny", "allow"):
            raise SpecError(f"network.default must be 'deny' or 'allow', got '{self.default}'")


@dataclass(frozen=True)
class SecretSpec:
    from_source: str  # "env"
    hosts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LimitsSpec:
    cpu: int = DEFAULT_CPU
    memory: str = DEFAULT_MEMORY


@dataclass(frozen=True)
class ProfileSpec:
    """A profile narrows the root spec — it can only restrict, never widen."""

    tools: ToolsSpec | None = None
    mounts: dict[str, str] | None = None  # path → mode override
    network: NetworkSpec | None = None


@dataclass(frozen=True)
class BulbiSpec:
    spec_version: str
    box: BoxSpec
    tools: ToolsSpec
    setup: SetupSpec = field(default_factory=SetupSpec)
    mounts: list[MountSpec] = field(default_factory=list)
    network: NetworkSpec = field(default_factory=NetworkSpec)
    secrets: dict[str, SecretSpec] = field(default_factory=dict)
    limits: LimitsSpec = field(default_factory=LimitsSpec)
    profiles: dict[str, ProfileSpec] = field(default_factory=dict)

    def content_hash(self) -> str:
        """Hash of the spec for image caching. Changes when the spec changes."""
        data = {
            "spec": self.spec_version,
            "agent": self.box.agent,
            "tools": self.tools.allow,
            "setup": self.setup.run,
            "limits": {"cpu": self.limits.cpu, "memory": self.limits.memory},
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]

    def resolve_profile(self, profile_name: str) -> BulbiSpec:
        """Return a new spec with the named profile merged in (narrowing only)."""
        if profile_name not in self.profiles:
            raise SpecError(f"unknown profile: '{profile_name}'")
        return merge_profile(self, self.profiles[profile_name])


class SpecError(Exception):
    """Raised when the spec is invalid."""


def load_spec(project_root: Path) -> BulbiSpec:
    """Load and parse bulbi.toml from the given directory."""
    spec_path = project_root / SPEC_FILENAME
    if not spec_path.exists():
        # Try pyproject.toml [tool.bulbi]
        pyproject_path = project_root / "pyproject.toml"
        if pyproject_path.exists():
            with open(pyproject_path, "rb") as f:
                pyproject = tomllib.load(f)
            if "tool" in pyproject and "bulbi" in pyproject["tool"]:
                return _parse_raw(pyproject["tool"]["bulbi"])
        raise SpecError(f"no {SPEC_FILENAME} found in {project_root}")

    with open(spec_path, "rb") as f:
        raw = tomllib.load(f)
    return _parse_raw(raw)


def _parse_raw(raw: dict[str, Any]) -> BulbiSpec:
    """Parse a raw TOML dict into a BulbiSpec."""
    spec_version = raw.get("spec", SPEC_VERSION)
    if spec_version != SPEC_VERSION:
        raise SpecError(f"unsupported spec version: {spec_version} (expected {SPEC_VERSION})")

    # Box
    box_raw = raw.get("box", {})
    if not box_raw.get("name"):
        raise SpecError("box.name is required")
    box = BoxSpec(name=box_raw["name"], agent=box_raw.get("agent", "claude"))

    # Tools
    tools_raw = raw.get("tools", {})
    tools = ToolsSpec(allow=tools_raw.get("allow", []))

    # Setup
    setup_raw = raw.get("setup", {})
    setup_run = setup_raw.get("run", [])
    if isinstance(setup_run, str):
        setup_run = [setup_run]
    setup = SetupSpec(run=setup_run)

    # Mounts
    mounts: list[MountSpec] = []
    for m in raw.get("mount", []):
        mounts.append(MountSpec(
            path=m["path"],
            mode=m.get("mode", "read-write"),
            exclude=m.get("exclude", []),
        ))

    # Network
    net_raw = raw.get("network", {})
    network = NetworkSpec(
        default=net_raw.get("default", "deny"),
        allow=net_raw.get("allow", []),
    )

    # Secrets
    secrets: dict[str, SecretSpec] = {}
    for name, s in raw.get("secrets", {}).items():
        secrets[name] = SecretSpec(
            from_source=s.get("from", "env"),
            hosts=s.get("hosts", []),
        )

    # Limits
    lim_raw = raw.get("limits", {})
    limits = LimitsSpec(
        cpu=lim_raw.get("cpu", DEFAULT_CPU),
        memory=lim_raw.get("memory", DEFAULT_MEMORY),
    )

    # Profiles
    profiles: dict[str, ProfileSpec] = {}
    for pname, praw in raw.get("profiles", {}).items():
        p_tools = None
        if "tools" in praw:
            p_tools = ToolsSpec(allow=praw["tools"].get("allow", []))
        p_mounts = praw.get("mounts")
        p_network = None
        if "network" in praw:
            p_network = NetworkSpec(
                default=praw["network"].get("default", "deny"),
                allow=praw["network"].get("allow", []),
            )
        profiles[pname] = ProfileSpec(tools=p_tools, mounts=p_mounts, network=p_network)

    return BulbiSpec(
        spec_version=spec_version,
        box=box,
        tools=tools,
        setup=setup,
        mounts=mounts,
        network=network,
        secrets=secrets,
        limits=limits,
        profiles=profiles,
    )


def merge_profile(root: BulbiSpec, profile: ProfileSpec) -> BulbiSpec:
    """Merge a profile into the root spec. The profile can only narrow access."""
    # Tools: profile tools must be a subset of root tools
    tools = root.tools
    if profile.tools is not None:
        extra = set(profile.tools.allow) - set(root.tools.allow)
        if extra:
            raise SpecError(f"profile widens tools: {extra}")
        tools = profile.tools

    # Network: profile domains must be a subset of root domains
    network = root.network
    if profile.network is not None:
        root_domains = set(root.network.allow)
        extra = set(profile.network.allow) - root_domains
        if extra:
            raise SpecError(f"profile widens network: {extra}")
        network = profile.network

    # Mounts: profile can only make read-write → read-only, not add new paths
    mounts = list(root.mounts)
    if profile.mounts is not None:
        root_paths = {m.path for m in root.mounts}
        for path, mode in profile.mounts.items():
            if path not in root_paths:
                raise SpecError(f"profile adds mount not in root: {path}")
            if mode not in ("read-only", "read-write"):
                raise SpecError(f"invalid mount mode in profile: {mode}")
        mounts = []
        for m in root.mounts:
            if m.path in profile.mounts:
                new_mode = profile.mounts[m.path]
                if m.mode == "read-only" and new_mode == "read-write":
                    raise SpecError(f"profile widens mount '{m.path}' from read-only to read-write")
                mounts.append(MountSpec(path=m.path, mode=new_mode, exclude=m.exclude))
            else:
                mounts.append(m)

    return BulbiSpec(
        spec_version=root.spec_version,
        box=root.box,
        tools=tools,
        setup=root.setup,
        mounts=mounts,
        network=network,
        secrets=root.secrets,
        limits=root.limits,
        profiles=root.profiles,
    )
