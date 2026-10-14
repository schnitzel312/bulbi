"""Progress notifications from a sandbox session."""

from __future__ import annotations

from collections.abc import Sequence

from bulbi.gitsafety.guard import GitSafetyReport
from bulbi.spec import BulbiSpec


class SandboxObserver:
    """Receives progress events; every hook is optional and does nothing by default."""

    def building_image(self, spec: BulbiSpec) -> None:
        """The box's image is about to be built (or reused from cache)."""

    def starting_gateway(self) -> None:
        """The images are ready; the network and its gateway are about to start."""

    def starting_container(self) -> None:
        """The gateway has loaded its rules; the box is about to start."""

    def running(self, label: str, command: Sequence[str]) -> None:
        """``command`` is about to run in the box; ``label`` says what it is for."""

    def git_report(self, report: GitSafetyReport) -> None:
        """A git safety scan ran (before an attach or after a session)."""
