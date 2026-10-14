"""The baseline: the project's git metadata as it was when the box was created (§2.1).

It lives in ``.bulbi/git-baseline.json`` (one file per profile), which the box can only
read: ``.bulbi/`` is mounted read-only into every box.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulbi.errors import GitSafetyError
from bulbi.gitsafety.config import ConfigEntry
from bulbi.gitsafety.exec_keys import ExecConfigRegistry
from bulbi.gitsafety.inventory import AdminDir, ConfigState, EntryKind, GitEntry, GitSnapshot
from bulbi.gitsafety.layout import within

BASELINE_STEM = "git-baseline"
BASELINE_SUFFIX = ".json"
_FORMAT_VERSION = 1
_UNSAFE_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_.-]")


def baseline_path(state_dir: Path, profile: str | None = None) -> Path:
    """``.bulbi/git-baseline.json``, or ``git-baseline-<profile>.json`` for a profile's box."""
    suffix = f"-{_UNSAFE_NAME_CHARS.sub('_', profile)}" if profile else ""
    return state_dir / f"{BASELINE_STEM}{suffix}{BASELINE_SUFFIX}"


@dataclass(frozen=True)
class GitBaseline:
    """What the box could write (``roots`` minus ``protected``) and what was there.

    Attributes:
        roots: Host directories the box can write (the read-write mounts).
        protected: Host paths inside ``roots`` the box cannot write (read-only overlays,
            masks, the isolated box repo's volume); changes there are the user's own.
        common_dir: The project's shared git directory, if it is a repository.
        snapshot: The git metadata found at box creation.
    """

    roots: tuple[Path, ...]
    protected: tuple[Path, ...] = ()
    common_dir: Path | None = None
    snapshot: GitSnapshot = field(default_factory=GitSnapshot)

    def box_writable(self, path: Path) -> bool:
        return any(within(path, root) for root in self.roots) and not any(
            within(path, protected) for protected in self.protected
        )

    def accepting(self, fresh: GitSnapshot, paths: Iterable[Path]) -> GitBaseline:
        """This baseline, trusting whatever ``fresh`` holds at or under ``paths``."""
        accepted = tuple(paths)

        def merged(old: Mapping[Path, Any], new: Mapping[Path, Any]) -> dict[Path, Any]:
            keep = {k: v for k, v in old.items() if not _under_any(k, accepted)}
            return keep | {k: v for k, v in new.items() if _under_any(k, accepted)}

        snapshot = GitSnapshot(
            merged(self.snapshot.entries, fresh.entries),
            merged(self.snapshot.admin_dirs, fresh.admin_dirs),
            merged(self.snapshot.configs, fresh.configs),
            merged(self.snapshot.hooks, fresh.hooks),
        )
        return GitBaseline(self.roots, self.protected, self.common_dir, snapshot)

    # ---- JSON --------------------------------------------------------------------------

    def to_json(self, registry: ExecConfigRegistry) -> str:
        """The baseline as JSON; of each config file only its exec-capable entries are kept."""
        snapshot = self.snapshot
        data = {
            "version": _FORMAT_VERSION,
            "roots": [str(path) for path in self.roots],
            "protected": [str(path) for path in self.protected],
            "common_dir": _optional(self.common_dir),
            "git_entries": {
                str(path): {"kind": entry.kind.value, "target": _optional(entry.target)}
                for path, entry in snapshot.entries.items()
            },
            "admin_dirs": {
                str(path): {"commondir": _optional(a.commondir), "gitdir": _optional(a.gitdir)}
                for path, a in snapshot.admin_dirs.items()
            },
            "configs": {
                str(path): {
                    "sha256": state.digest,
                    "exec_entries": None
                    if state.entries is None
                    else [
                        [entry.key, entry.value]
                        for entry in state.entries
                        if registry.is_exec(entry.key, entry.value)
                    ],
                }
                for path, state in snapshot.configs.items()
            },
            "hooks": {str(path): digest for path, digest in snapshot.hooks.items()},
        }
        return json.dumps(data, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> GitBaseline:
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("version") != _FORMAT_VERSION:
            raise ValueError("unsupported baseline format")
        snapshot = GitSnapshot(
            entries={
                Path(path): GitEntry(EntryKind(item["kind"]), _path(item["target"]))
                for path, item in data["git_entries"].items()
            },
            admin_dirs={
                Path(path): AdminDir(_path(item["commondir"]), _path(item["gitdir"]))
                for path, item in data["admin_dirs"].items()
            },
            configs={
                Path(path): ConfigState(
                    item["sha256"],
                    None
                    if item["exec_entries"] is None
                    else tuple(ConfigEntry(key, value) for key, value in item["exec_entries"]),
                )
                for path, item in data["configs"].items()
            },
            hooks={Path(path): digest for path, digest in data["hooks"].items()},
        )
        return cls(
            roots=tuple(Path(path) for path in data["roots"]),
            protected=tuple(Path(path) for path in data["protected"]),
            common_dir=_path(data["common_dir"]),
            snapshot=snapshot,
        )


class BaselineStore:
    """Reads and atomically writes one baseline file."""

    def __init__(self, path: Path, registry: ExecConfigRegistry | None = None) -> None:
        self._path = path
        self._registry = registry or ExecConfigRegistry.builtin()

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> GitBaseline | None:
        if not self._path.is_file():
            return None
        try:
            return GitBaseline.from_json(self._path.read_text())
        except (ValueError, KeyError, TypeError) as exc:
            raise GitSafetyError(
                f"{self._path} is unreadable ({exc}); run `bulbi restart` to record a new one"
            ) from exc

    def save(self, baseline: GitBaseline) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_name(f".{self._path.name}.tmp")
        temporary.write_text(baseline.to_json(self._registry))
        os.replace(temporary, self._path)


def _under_any(path: Path, directories: Iterable[Path]) -> bool:
    return any(within(path, directory) for directory in directories)


def _optional(path: Path | None) -> str | None:
    return None if path is None else str(path)


def _path(value: str | None) -> Path | None:
    return None if value is None else Path(value)
