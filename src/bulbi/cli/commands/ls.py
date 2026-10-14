"""``bulbi ls``: list Bulbi boxes with their active sessions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from bulbi.cli.commands.base import BulbiCommand
from bulbi.cli.context import AppContext
from bulbi.cli.render.boxes import NOT_AVAILABLE, BoxRow, BoxTableRenderer
from bulbi.constants import DOCKER_LABEL_PROFILE, DOCKER_LABEL_PROJECT
from bulbi.container.manager import ContainerState

Clock = Callable[[], datetime]


def format_uptime(started_at: str | None, now: datetime) -> str:
    """``1h 05m`` style duration since ``started_at`` (Docker's RFC 3339 timestamp)."""
    if not started_at:
        return NOT_AVAILABLE
    try:
        started = datetime.fromisoformat(started_at[:26].rstrip("Z") + "+00:00")
    except ValueError:
        return NOT_AVAILABLE
    minutes = max(int((now - started).total_seconds() // 60), 0)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m" if hours else f"{minutes}m"


class ListCommand(BulbiCommand):
    name = "ls"
    help = "List bulbi boxes, their projects and active sessions."

    def __init__(self, clock: Clock = lambda: datetime.now(UTC)) -> None:
        self._clock = clock

    def execute(self, app: AppContext) -> None:
        tracker = app.session_tracker()
        boxes = app.box_manager().list_boxes()
        app.gateway_manager().reap(app.box_manager().list_containers())
        now = self._clock()
        rows = [self._row(box, tracker.active_sessions(box.id) if box.running else 0, now)
                for box in boxes]  # fmt: skip
        BoxTableRenderer(app.console).render(rows)

    @staticmethod
    def _row(box: ContainerState, sessions: int, now: datetime) -> BoxRow:
        return BoxRow(
            name=box.name,
            project=box.labels.get(DOCKER_LABEL_PROJECT, NOT_AVAILABLE),
            profile=box.labels.get(DOCKER_LABEL_PROFILE, ""),
            status=box.status,
            sessions=sessions,
            uptime=format_uptime(box.started_at, now) if box.running else NOT_AVAILABLE,
        )
