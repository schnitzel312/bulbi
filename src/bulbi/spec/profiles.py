"""Applying named profiles, which may only narrow the root spec."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import replace

from bulbi.errors import SpecError
from bulbi.spec.models import (
    BulbiSpec,
    MountMode,
    MountSpec,
    NetworkDefault,
    NetworkSpec,
    ProfileSpec,
)


class ProfileMerger:
    """Checks that a profile only narrows the root spec and merges it in.

    :meth:`violations` is the single source of truth for the narrowing rules; both
    :meth:`merge` (fail fast) and spec validation (report everything) use it.
    """

    def resolve(self, spec: BulbiSpec, profile_name: str) -> BulbiSpec:
        """Return ``spec`` with the named profile applied."""
        if profile_name not in spec.profiles:
            raise SpecError(f"unknown profile: '{profile_name}'")
        return self.merge(spec, spec.profiles[profile_name])

    def merge(self, root: BulbiSpec, profile: ProfileSpec) -> BulbiSpec:
        """Return ``root`` narrowed by ``profile``; raise if the profile widens anything."""
        violation = next(self.violations(root, profile), None)
        if violation is not None:
            raise SpecError(f"profile {violation}")
        return replace(
            root,
            tools=profile.tools if profile.tools is not None else root.tools,
            network=profile.network if profile.network is not None else root.network,
            mounts=self._merged_mounts(root.mounts, profile.mounts or {}),
        )

    def violations(self, root: BulbiSpec, profile: ProfileSpec) -> Iterator[str]:
        """Yield a description of every way ``profile`` would widen ``root``."""
        if profile.tools is not None:
            yield from self._extra_entries("tools", profile.tools.allow, root.tools.allow)
        if profile.network is not None:
            yield from self._network_default_violations(root.network, profile.network)
            yield from self._extra_entries("network", profile.network.allow, root.network.allow)
        if profile.mounts is not None:
            yield from self._mount_violations(root.mounts, profile.mounts)

    @staticmethod
    def _network_default_violations(root: NetworkSpec, narrowed: NetworkSpec) -> Iterator[str]:
        if root.default is NetworkDefault.DENY and narrowed.default is NetworkDefault.ALLOW:
            yield (
                f"widens network default from '{NetworkDefault.DENY}' to '{NetworkDefault.ALLOW}'"
            )

    @staticmethod
    def _extra_entries(
        section: str, narrowed: Iterable[str], root: Iterable[str]
    ) -> Iterator[str]:
        extra = sorted(set(narrowed) - set(root))
        if extra:
            yield f"widens {section}: {extra} not in root"

    @staticmethod
    def _mount_violations(
        root_mounts: list[MountSpec], overrides: dict[str, str]
    ) -> Iterator[str]:
        root_modes = {mount.path: mount.mode for mount in root_mounts}
        valid_modes = {mode.value for mode in MountMode}
        for path, mode in overrides.items():
            if path not in root_modes:
                yield f"adds mount '{path}' not in root"
            elif mode not in valid_modes:
                yield f"sets invalid mount mode '{mode}' for '{path}'"
            elif root_modes[path] is MountMode.READ_ONLY and mode == MountMode.READ_WRITE:
                yield f"widens mount '{path}' from read-only to read-write"

    @staticmethod
    def _merged_mounts(root_mounts: list[MountSpec], overrides: dict[str, str]) -> list[MountSpec]:
        return [
            replace(mount, mode=MountMode(overrides[mount.path]))
            if mount.path in overrides
            else mount
            for mount in root_mounts
        ]
