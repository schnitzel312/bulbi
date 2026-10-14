"""Progress notifications from a sandbox session."""

from __future__ import annotations

from collections.abc import Sequence

from bulbi.spec import BulbiSpec


class SandboxObserver:
    """Receives progress events; every hook is optional and does nothing by default."""

    def building_image(self, spec: BulbiSpec) -> None:
        """The box's image is about to be built (or reused from cache)."""

    def starting_container(self) -> None:
        """The proxy is up and the container is about to start."""

    def running(self, label: str, command: Sequence[str]) -> None:
        """``command`` is about to run in the box; ``label`` says what it is for."""
