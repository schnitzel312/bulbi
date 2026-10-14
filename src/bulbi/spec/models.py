"""Immutable data models describing a parsed ``bulbi.toml``."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeVar

from bulbi.constants import (
    DEFAULT_AGENT,
    DEFAULT_CPU,
    DEFAULT_GIT_SCAN_BUDGET,
    DEFAULT_GIT_SCAN_SKIP,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MEMORY,
)
from bulbi.errors import SpecError

_CONTENT_HASH_LENGTH = 16
_MEMORY_PATTERN = re.compile(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)$")
_DURATION_PATTERN = re.compile(r"^(\d+)\s*([smh]?)$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}
_MEMORY_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

_EnumT = TypeVar("_EnumT", bound=StrEnum)


class MountMode(StrEnum):
    """Access mode of a bind mount."""

    READ_ONLY = "read-only"
    READ_WRITE = "read-write"


class NetworkDefault(StrEnum):
    """What the gateway does with destinations no rule mentions."""

    DENY = "deny"
    ALLOW = "allow"


class GitModeKind(StrEnum):
    """How the box reaches the project's git metadata (``[git] mode``)."""

    GUARDED = "guarded"  # Host metadata mounted; Bulbi scans and neutralises changes.
    ISOLATED = "isolated"  # The box works on its own clone in a volume.


class FindingPolicy(StrEnum):
    """What Bulbi does about dangerous git metadata (``[git] on_finding``)."""

    QUARANTINE = "quarantine"  # Move it aside (restorable) and carry on.
    BLOCK = "block"  # Change nothing and refuse to attach.


class SecretSource(StrEnum):
    """Where Bulbi reads a secret's value on the host (``from``)."""

    ENV = "env"
    FILE = "file"
    KEYCHAIN = "keychain"
    COMMAND = "command"


class SecretTarget(StrEnum):
    """How the box receives a secret (``to``)."""

    ENV = "env"
    FILE = "file"


@dataclass(frozen=True)
class BoxSpec:
    """Identity of the box, which agent it runs, and how long it lingers when idle."""

    name: str
    agent: str = DEFAULT_AGENT
    idle_timeout: str = DEFAULT_IDLE_TIMEOUT

    def idle_timeout_seconds(self) -> int:
        """``idle_timeout`` (``"0"``, ``"90s"``, ``"10m"``, ``"2h"``) in seconds."""
        return _duration_seconds(self.idle_timeout, "box.idle_timeout")


@dataclass(frozen=True)
class ProjectSpec:
    """How the project's checkouts are found (git worktrees, §9)."""

    worktree_dirs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class GitSpec:
    """Git safety (``[git]``, see docs/specs/git-safety.md).

    ``scan_budget`` bounds how long one scan may walk the mounted checkouts; ``skip``
    names directories the walk never enters (large, ignored trees such as
    ``node_modules``).
    """

    mode: GitModeKind = GitModeKind.GUARDED
    on_finding: FindingPolicy = FindingPolicy.QUARANTINE
    scan_budget: str = DEFAULT_GIT_SCAN_BUDGET
    skip: list[str] = field(default_factory=lambda: list(DEFAULT_GIT_SCAN_SKIP))

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _parse_enum(GitModeKind, self.mode, "git.mode"))
        object.__setattr__(
            self, "on_finding", _parse_enum(FindingPolicy, self.on_finding, "git.on_finding")
        )

    def scan_budget_seconds(self) -> int:
        return _duration_seconds(self.scan_budget, "git.scan_budget")


@dataclass(frozen=True)
class ToolsSpec:
    """Tool references (``name`` or ``name@version``) installed in the image."""

    allow: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SetupSpec:
    """Shell commands run once, the first time the container starts."""

    run: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MountSpec:
    """A host path bind-mounted into the container workspace."""

    path: str
    mode: MountMode = MountMode.READ_WRITE
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _parse_enum(MountMode, self.mode, "mount mode"))

    @property
    def is_writable(self) -> bool:
        return self.mode is MountMode.READ_WRITE


@dataclass(frozen=True)
class NetworkSpec:
    """Outbound network policy enforced by the gateway (see ``bulbi.gateway``).

    ``allow`` and ``deny`` hold rule strings; ``bulbi.gateway.rules`` defines their syntax.
    """

    default: NetworkDefault = NetworkDefault.DENY
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "default", _parse_enum(NetworkDefault, self.default, "network.default")
        )


@dataclass(frozen=True)
class SecretSpec:
    """One ``[secrets]`` entry (spec §10.1).

    ``from_source`` and ``to`` are coerced to their enums when recognised and otherwise
    kept as the raw TOML value (whatever its type), so validation can report them.
    ``hosts`` is accepted for compatibility and ignored until ``to = "inject"`` exists.
    """

    from_source: SecretSource | str | None
    source: str | None = None
    to: SecretTarget | str = SecretTarget.ENV
    path: str | None = None
    hosts: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        object.__setattr__(self, "from_source", _known(SecretSource, self.from_source))
        object.__setattr__(self, "to", _known(SecretTarget, self.to))


@dataclass(frozen=True)
class LimitsSpec:
    """Container resource limits."""

    cpu: int = DEFAULT_CPU
    memory: str = DEFAULT_MEMORY

    def memory_bytes(self) -> int:
        """``memory`` (e.g. ``4GB``, binary units) in bytes."""
        match = _MEMORY_PATTERN.match(self.memory.upper())
        if not match:
            raise SpecError(f"invalid memory string: '{self.memory}'")
        return int(float(match.group(1)) * _MEMORY_UNITS[match.group(2)])


@dataclass(frozen=True)
class ProfileSpec:
    """A named override that may only narrow the root spec, never widen it."""

    tools: ToolsSpec | None = None
    mounts: dict[str, str] | None = None  # mount path -> mode override
    network: NetworkSpec | None = None


@dataclass(frozen=True)
class BulbiSpec:
    """The complete, parsed sandbox spec."""

    spec_version: str
    box: BoxSpec
    tools: ToolsSpec
    setup: SetupSpec = field(default_factory=SetupSpec)
    mounts: list[MountSpec] = field(default_factory=list)
    network: NetworkSpec = field(default_factory=NetworkSpec)
    secrets: dict[str, SecretSpec] = field(default_factory=dict)
    limits: LimitsSpec = field(default_factory=LimitsSpec)
    profiles: dict[str, ProfileSpec] = field(default_factory=dict)
    project: ProjectSpec = field(default_factory=ProjectSpec)
    git: GitSpec = field(default_factory=GitSpec)

    def content_hash(self) -> str:
        """Short hash of everything that affects the built image."""
        image_inputs = {
            "spec": self.spec_version,
            "agent": self.box.agent,
            "tools": self.tools.allow,
            "setup": self.setup.run,
            "limits": {"cpu": self.limits.cpu, "memory": self.limits.memory},
        }
        encoded = json.dumps(image_inputs, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()[:_CONTENT_HASH_LENGTH]


def _duration_seconds(value: str, label: str) -> int:
    """A duration (``"0"``, ``"90s"``, ``"10m"``, ``"2h"``) in seconds."""
    match = _DURATION_PATTERN.match(str(value).strip().lower())
    if not match:
        raise SpecError(f"{label} must look like '0', '30s', '10m' or '1h', got '{value}'")
    return int(match.group(1)) * _DURATION_UNITS[match.group(2) or "s"]


def _known(enum_type: type[_EnumT], value: object) -> object:
    """``value`` as a member of ``enum_type`` if it names one; otherwise unchanged."""
    if isinstance(value, str) and value in {member.value for member in enum_type}:
        return enum_type(value)
    return value


def _parse_enum(enum_type: type[_EnumT], value: str, label: str) -> _EnumT:
    """Coerce ``value`` into ``enum_type`` or raise a :class:`SpecError`."""
    try:
        return enum_type(value)
    except ValueError:
        choices = " or ".join(f"'{member.value}'" for member in enum_type)
        raise SpecError(f"{label} must be {choices}, got '{value}'") from None
