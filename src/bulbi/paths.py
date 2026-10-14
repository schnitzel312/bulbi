"""Path helpers shared by host-side and box-side code (standard library only)."""

from __future__ import annotations

from pathlib import Path

HOME_MARKER = "~"


def expand_home(raw: str, home: str | Path) -> str:
    """Expand a leading ``~`` or ``~/`` to ``home``; anything else (incl. ``~user``) is kept.

    ``home`` is the host user's home for host paths, or the box user's home for paths
    inside the box, so one rule serves both.
    """
    if raw == HOME_MARKER or raw.startswith(f"{HOME_MARKER}/"):
        return str(home) + raw[len(HOME_MARKER) :]
    return raw
