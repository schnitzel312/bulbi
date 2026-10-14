"""Immutable data models describing a parsed ``bulbi.toml``."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeVar

from bulbi.constants import DEFAULT_AGENT, DEFAULT_CPU, DEFAULT_MEMORY
from bulbi.errors import SpecError

_CONTENT_HASH_LENGTH = 16
_MEMORY_PATTERN = re.compile(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)$")
_MEMORY_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}

_EnumT = TypeVar("_EnumT", bound=StrEnum)


class MountMode(StrEnum):
    """Access mode of a bind mount."""

    READ_ONLY = "read-only"
    READ_WRITE = "read-write"


class NetworkDefault(StrEnum):
    """What the proxy does with domains that are not explicitly allowed."""

    DENY = "deny"
    ALLOW = "allow"


class SecretSource(StrEnum):
    """Where a secret's value comes from on the host."""

    ENV = "env"


@dataclass(frozen=True)
class BoxSpec:
    """Identity of the box: its name and which agent it runs."""

    name: str
    agent: str = DEFAULT_AGENT


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
    """A host secret and the hosts it may be sent to.

    Secrets are parsed and validated only; Bulbi does not inject them anywhere yet.
    ``from_source`` is coerced to :class:`SecretSource` when recognised and otherwise
    kept as the raw value (whatever its type), so validation can report it.
    """

    from_source: SecretSource | str
    hosts: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Raw TOML may hold any type here (e.g. a list); only strings can name a source.
        source: object = self.from_source
        if isinstance(source, str) and source in {member.value for member in SecretSource}:
            object.__setattr__(self, "from_source", SecretSource(self.from_source))


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


def _parse_enum(enum_type: type[_EnumT], value: str, label: str) -> _EnumT:
    """Coerce ``value`` into ``enum_type`` or raise a :class:`SpecError`."""
    try:
        return enum_type(value)
    except ValueError:
        choices = " or ".join(f"'{member.value}'" for member in enum_type)
        raise SpecError(f"{label} must be {choices}, got '{value}'") from None
