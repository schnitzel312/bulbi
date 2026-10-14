"""Rich markup helpers shared by the renderers."""

from __future__ import annotations

ALLOWED_STYLE = "green"
DENIED_STYLE = "red"
CAUTION_STYLE = "yellow"
EMPTY_CELL = "[dim]none[/dim]"


def styled(text: str, style: str) -> str:
    return f"[{style}]{text}[/{style}]"
