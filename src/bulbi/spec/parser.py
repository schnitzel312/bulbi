"""Turns the raw TOML mapping of a spec into :class:`BulbiSpec` models."""

from __future__ import annotations

from typing import Any

from bulbi.constants import (
    DEFAULT_AGENT,
    DEFAULT_CPU,
    DEFAULT_GIT_SCAN_BUDGET,
    DEFAULT_GIT_SCAN_SKIP,
    DEFAULT_IDLE_TIMEOUT,
    DEFAULT_MEMORY,
    SPEC_VERSION,
)
from bulbi.errors import SpecError
from bulbi.spec.models import (
    BoxSpec,
    BulbiSpec,
    FindingPolicy,
    GitModeKind,
    GitSpec,
    LimitsSpec,
    MountMode,
    MountSpec,
    NetworkDefault,
    NetworkSpec,
    ProfileSpec,
    ProjectSpec,
    SecretSpec,
    SecretTarget,
    SetupSpec,
    ToolsSpec,
)

RawTable = dict[str, Any]


class SpecParser:
    """Parses one raw spec table (``bulbi.toml`` or ``[tool.bulbi]``) section by section."""

    def parse(self, raw: RawTable) -> BulbiSpec:
        return BulbiSpec(
            spec_version=self._parse_version(raw),
            box=self._parse_box(raw.get("box", {})),
            tools=self._parse_tools(raw.get("tools", {})),
            setup=self._parse_setup(raw.get("setup", {})),
            mounts=[self._parse_mount(entry) for entry in raw.get("mount", [])],
            network=self._parse_network(raw.get("network", {})),
            secrets={
                name: self._parse_secret(entry) for name, entry in raw.get("secrets", {}).items()
            },
            limits=self._parse_limits(raw.get("limits", {})),
            profiles={
                name: self._parse_profile(entry) for name, entry in raw.get("profiles", {}).items()
            },
            project=ProjectSpec(
                worktree_dirs=list(raw.get("project", {}).get("worktree_dirs", []))
            ),
            git=self._parse_git(raw.get("git", {})),
        )

    @staticmethod
    def _parse_version(raw: RawTable) -> str:
        version = str(raw.get("spec", SPEC_VERSION))
        if version != SPEC_VERSION:
            raise SpecError(f"unsupported spec version: {version} (expected {SPEC_VERSION})")
        return version

    @staticmethod
    def _parse_box(raw: RawTable) -> BoxSpec:
        if not raw.get("name"):
            raise SpecError("box.name is required")
        return BoxSpec(
            name=raw["name"],
            agent=raw.get("agent", DEFAULT_AGENT),
            idle_timeout=str(raw.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)),
        )

    @staticmethod
    def _parse_tools(raw: RawTable) -> ToolsSpec:
        return ToolsSpec(allow=list(raw.get("allow", [])))

    @staticmethod
    def _parse_setup(raw: RawTable) -> SetupSpec:
        commands = raw.get("run", [])
        if isinstance(commands, str):
            commands = [commands]
        return SetupSpec(run=list(commands))

    @staticmethod
    def _parse_mount(raw: RawTable) -> MountSpec:
        if "path" not in raw:
            raise SpecError("mount.path is required")
        return MountSpec(
            path=raw["path"],
            mode=raw.get("mode", MountMode.READ_WRITE),
            exclude=list(raw.get("exclude", [])),
        )

    @staticmethod
    def _parse_network(raw: RawTable) -> NetworkSpec:
        return NetworkSpec(
            default=raw.get("default", NetworkDefault.DENY),
            allow=list(raw.get("allow", [])),
            deny=list(raw.get("deny", [])),
        )

    @staticmethod
    def _parse_secret(raw: RawTable) -> SecretSpec:
        return SecretSpec(
            from_source=raw.get("from"),
            source=raw.get("source"),
            to=raw.get("to", SecretTarget.ENV),
            path=raw.get("path"),
            hosts=list(raw.get("hosts", [])),
        )

    @staticmethod
    def _parse_git(raw: RawTable) -> GitSpec:
        return GitSpec(
            mode=raw.get("mode", GitModeKind.GUARDED),
            on_finding=raw.get("on_finding", FindingPolicy.QUARANTINE),
            scan_budget=str(raw.get("scan_budget", DEFAULT_GIT_SCAN_BUDGET)),
            skip=list(raw.get("skip", DEFAULT_GIT_SCAN_SKIP)),
        )

    @staticmethod
    def _parse_limits(raw: RawTable) -> LimitsSpec:
        return LimitsSpec(
            cpu=raw.get("cpu", DEFAULT_CPU),
            memory=raw.get("memory", DEFAULT_MEMORY),
        )

    def _parse_profile(self, raw: RawTable) -> ProfileSpec:
        return ProfileSpec(
            tools=self._parse_tools(raw["tools"]) if "tools" in raw else None,
            mounts=raw.get("mounts"),
            network=self._parse_network(raw["network"]) if "network" in raw else None,
        )
