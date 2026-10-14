"""The proxy's JSON-lines audit log: one entry per allowed or denied request."""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from bulbi.constants import LOG_DIR, LOG_FILENAME
from bulbi.errors import AuditLogError

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]


class AuditAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class LogEntry:
    """One proxied request. Field order is the on-disk JSON key order."""

    timestamp: str
    domain: str
    action: str
    method: str
    url: str

    @property
    def denied(self) -> bool:
        return self.action == AuditAction.DENY

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> LogEntry:
        """Build an entry from a decoded log line; missing fields become empty strings."""
        return cls(
            timestamp=str(data.get("timestamp", "")),
            domain=str(data.get("domain", "")),
            action=str(data.get("action", "")),
            method=str(data.get("method", "")),
            url=str(data.get("url", "")),
        )


def audit_log_path(project_root: Path) -> Path:
    """Where a project's proxy log lives."""
    return project_root / LOG_DIR / LOG_FILENAME


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuditLogWriter:
    """Appends entries to the log; safe to call from the proxy's handler threads."""

    def __init__(self, path: Path, clock: Clock = _utc_now) -> None:
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, domain: str, action: AuditAction, method: str, url: str) -> None:
        entry = LogEntry(
            timestamp=self._clock().isoformat(),
            domain=domain,
            action=action,
            method=method,
            url=url,
        )
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a") as handle:
                    handle.write(entry.to_json() + "\n")
        except OSError:
            # Auditing must never take the proxy down; the failure is still reported.
            logger.exception("Failed to write proxy log entry")


class AuditLogReader:
    """Reads entries back for ``bulbi log``."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.is_file()

    def entries(self) -> list[LogEntry]:
        """All entries, oldest first; an absent log has none."""
        if not self.exists():
            return []
        entries = []
        for line_number, line in enumerate(self._path.read_text().splitlines(), start=1):
            if line.strip():
                entries.append(self._parse_line(line, line_number))
        return entries

    def denied(self) -> list[LogEntry]:
        return [entry for entry in self.entries() if entry.denied]

    def _parse_line(self, line: str, line_number: int) -> LogEntry:
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditLogError(f"Failed to parse log file: line {line_number}: {exc}") from exc
        if not isinstance(data, dict):
            raise AuditLogError(f"Failed to parse log file: line {line_number} is not an object")
        return LogEntry.from_mapping(data)
