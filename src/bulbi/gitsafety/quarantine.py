"""Moving dangerous git metadata aside, and putting it back (spec §2.3).

Each neutralisation run is one record: its items live under
``.bulbi/quarantine/<id>/<relpath>`` and its manifest in ``.bulbi/quarantine/<id>.json``.
Nothing is ever deleted: moved items move, edited files keep a backup, and a restore
keeps the neutralised version inside the record.
"""

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from bulbi.errors import GitSafetyError
from bulbi.gateway.audit import Clock, utc_now
from bulbi.gitsafety.config import GitConfigEditor
from bulbi.gitsafety.findings import GitFinding
from bulbi.gitsafety.layout import within

QUARANTINE_DIR = "quarantine"
MANIFEST_SUFFIX = ".json"
EXTERNAL_DIR = "_external"
NEUTRALISED_SUFFIX = ".neutralised"
_ID_FORMAT = "%Y%m%dT%H%M%SZ"
_ID_PATTERN = re.compile(r"^\d{8}T\d{6}Z(?:-\d+)?$")


class ItemAction(StrEnum):
    MOVED = "moved"
    COMMENTED = "commented"


@dataclass(frozen=True)
class QuarantinedItem:
    """One thing set aside: where it was, where it is now, and why."""

    action: ItemAction
    original: Path
    stored: Path
    reason: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "action": self.action.value,
            "original": str(self.original),
            "stored": str(self.stored),
            "reason": self.reason,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> QuarantinedItem:
        return cls(
            ItemAction(data["action"]),
            Path(data["original"]),
            Path(data["stored"]),
            data["reason"],
            data["detail"],
        )


@dataclass(frozen=True)
class QuarantineRecord:
    """A manifest: one neutralisation run."""

    id: str
    created: str
    items: tuple[QuarantinedItem, ...]
    restored: str | None = None


class QuarantineSession:
    """Collects the items of one record while findings are neutralised."""

    def __init__(self, store: QuarantineStore, record_id: str, editor: GitConfigEditor) -> None:
        self._store = store
        self.id = record_id
        self._editor = editor
        self.items: list[QuarantinedItem] = []

    def move(self, finding: GitFinding, path: Path) -> Path:
        stored = self._store.slot(self.id, path)
        stored.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(stored))
        self.items.append(self._item(ItemAction.MOVED, finding, path, stored))
        return stored

    def comment_out(
        self, finding: GitFinding, path: Path, key: str, trusted: Sequence[str | None]
    ) -> Path:
        stored = self._store.slot(self.id, path)
        stored.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, stored)
        self.items.append(self._item(ItemAction.COMMENTED, finding, path, stored))
        self._editor.neutralise(path, key, trusted)
        return stored

    @staticmethod
    def _item(
        action: ItemAction, finding: GitFinding, original: Path, stored: Path
    ) -> QuarantinedItem:
        return QuarantinedItem(action, original, stored, finding.reason.value, finding.detail)


class QuarantineStore:
    """``.bulbi/quarantine`` of one project."""

    def __init__(
        self,
        state_dir: Path,
        project_root: Path,
        editor_factory: Callable[[], GitConfigEditor],
        clock: Clock = utc_now,
    ) -> None:
        self._root = state_dir / QUARANTINE_DIR
        self._project_root = project_root
        self._editor_factory = editor_factory
        self._clock = clock

    @property
    def root(self) -> Path:
        return self._root

    # ---- writing -----------------------------------------------------------------------

    def open(self) -> QuarantineSession:
        base = self._clock().strftime(_ID_FORMAT)
        record_id, counter = base, 1
        while self._manifest(record_id).exists() or (self._root / record_id).exists():
            counter += 1
            record_id = f"{base}-{counter}"
        return QuarantineSession(self, record_id, self._editor_factory())

    def close(self, session: QuarantineSession) -> QuarantineRecord | None:
        """Write the session's manifest; ``None`` if nothing was set aside."""
        if not session.items:
            return None
        record = QuarantineRecord(session.id, self._clock().isoformat(), tuple(session.items))
        self._write(record)
        return record

    def slot(self, record_id: str, original: Path) -> Path:
        """A free path in the record for ``original`` (``<id>/<path relative to project>``)."""
        if within(original, self._project_root):
            relative = original.relative_to(self._project_root)
        else:
            relative = Path(EXTERNAL_DIR, *original.parts[1:])
        candidate = self._root / record_id / relative
        counter = 1
        while candidate.exists() or candidate.is_symlink():
            counter += 1
            candidate = candidate.with_name(f"{relative.name}.{counter}")
        return candidate

    # ---- reading and restoring ---------------------------------------------------------

    def records(self) -> list[QuarantineRecord]:
        if not self._root.is_dir():
            return []
        manifests = sorted(self._root.glob(f"*{MANIFEST_SUFFIX}"))
        return [self.load(path.stem) for path in manifests if _ID_PATTERN.match(path.stem)]

    def load(self, record_id: str) -> QuarantineRecord:
        if not _ID_PATTERN.match(record_id):
            raise GitSafetyError(f"'{record_id}' is not a quarantine id")
        manifest = self._manifest(record_id)
        if not manifest.is_file():
            raise GitSafetyError(f"no quarantine record '{record_id}' in {self._root}")
        try:
            data = json.loads(manifest.read_text())
            items = tuple(QuarantinedItem.from_dict(item) for item in data["items"])
            return QuarantineRecord(record_id, data["created"], items, data.get("restored"))
        except (ValueError, KeyError, TypeError) as exc:
            raise GitSafetyError(f"quarantine record {manifest} is unreadable: {exc}") from exc

    def restore(self, record_id: str) -> QuarantineRecord:
        """Put every item of a record back; refuses to overwrite anything."""
        record = self.load(record_id)
        if record.restored is not None:
            raise GitSafetyError(f"quarantine record {record_id} was already restored")
        record_dir = self._root / record_id
        for item in record.items:
            if not within(item.stored, record_dir) or not item.original.is_absolute():
                raise GitSafetyError(f"quarantine record {record_id} is malformed")
        for item in record.items:
            if item.action is ItemAction.MOVED and (
                item.original.exists() or item.original.is_symlink()
            ):
                raise GitSafetyError(
                    f"{item.original} exists again; move it away before restoring {record_id}"
                )
        for item in reversed(record.items):
            if item.action is ItemAction.COMMENTED and item.original.exists():
                shutil.move(str(item.original), str(_free(item.stored, NEUTRALISED_SUFFIX)))
            item.original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(item.stored), str(item.original))
        restored = QuarantineRecord(
            record.id, record.created, record.items, self._clock().isoformat()
        )
        self._write(restored)
        return restored

    def _manifest(self, record_id: str) -> Path:
        return self._root / f"{record_id}{MANIFEST_SUFFIX}"

    def _write(self, record: QuarantineRecord) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        data = {
            "id": record.id,
            "created": record.created,
            "restored": record.restored,
            "items": [item.to_dict() for item in record.items],
        }
        self._manifest(record.id).write_text(json.dumps(data, indent=2))


def _free(path: Path, suffix: str) -> Path:
    candidate, counter = path.with_name(path.name + suffix), 1
    while candidate.exists():
        counter += 1
        candidate = path.with_name(f"{path.name}{suffix}.{counter}")
    return candidate
