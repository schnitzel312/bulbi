"""The network audit log: one JSON line per DNS answer or connection attempt.

Keys ``timestamp, domain, action, method, url`` are unchanged from the HTTP proxy era
(``method`` is now ``DNS``, ``TCP`` or ``UDP``); ``reason, rule, ip, port, proto`` are
new. Old lines without the new keys still read fine.

Standard-library only: the gateway writes this file; ``bulbi log`` reads it.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bulbi.constants import LOG_DIR, LOG_FILENAME
from bulbi.errors import AuditLogError

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
DENY_ACTION = "deny"


@dataclass(frozen=True)
class LogEntry:
    """One audited event. Field order is the on-disk JSON key order."""

    timestamp: str
    domain: str
    action: str
    method: str
    url: str
    reason: str | None = None
    rule: str | None = None
    ip: str | None = None
    port: int | None = None
    proto: str | None = None

    @property
    def denied(self) -> bool:
        return self.action == DENY_ACTION

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> LogEntry:
        """Build an entry from a decoded line; missing legacy keys become empty strings."""
        port = data.get("port")
        return cls(
            timestamp=str(data.get("timestamp", "")),
            domain=str(data.get("domain", "")),
            action=str(data.get("action", "")),
            method=str(data.get("method", "")),
            url=str(data.get("url", "")),
            reason=_optional_str(data.get("reason")),
            rule=_optional_str(data.get("rule")),
            ip=_optional_str(data.get("ip")),
            port=port if isinstance(port, int) else None,
            proto=_optional_str(data.get("proto")),
        )


def _optional_str(value: object) -> str | None:
    return None if value is None else str(value)


def audit_log_path(project_root: Path) -> Path:
    """Where a project's network audit log lives."""
    return project_root / LOG_DIR / LOG_FILENAME


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp(clock: Clock = utc_now) -> str:
    return clock().isoformat()


class AuditLogWriter:
    """Appends entries; safe to call from several threads.

    ``owner`` (uid, gid) makes the file belong to the host user when the gateway
    writes it as root into a bind-mounted directory.
    """

    def __init__(self, path: Path, owner: tuple[int, int] | None = None) -> None:
        self._path = path
        self._owner = owner
        self._lock = threading.Lock()

    def write(self, entry: LogEntry) -> None:
        try:
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                created = not self._path.exists()
                with self._path.open("a") as handle:
                    handle.write(entry.to_json() + "\n")
                if created and self._owner is not None:
                    os.chown(self._path, *self._owner)
        except OSError:
            # Auditing must never take the gateway down; the failure is still reported.
            logger.exception("Failed to write audit log entry")


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

    @staticmethod
    def _parse_line(line: str, line_number: int) -> LogEntry:
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise AuditLogError(f"Failed to parse log file: line {line_number}: {exc}") from exc
        if not isinstance(data, dict):
            raise AuditLogError(f"Failed to parse log file: line {line_number} is not an object")
        return LogEntry.from_mapping(data)
