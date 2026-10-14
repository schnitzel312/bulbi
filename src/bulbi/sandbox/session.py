"""One terminal's session in the project's shared box (spec §8.2, §9.1)."""

from __future__ import annotations

from collections.abc import Sequence
from types import TracebackType

from bulbi.container.manager import RunningBox
from bulbi.errors import SandboxError
from bulbi.image.entrypoint import SESSION_MARKER_ENV, SESSION_MARKER_VALUE
from bulbi.sandbox.observer import SandboxObserver
from bulbi.sandbox.orchestrator import BoxOrchestrator, SandboxServices

SESSION_ENVIRONMENT = {SESSION_MARKER_ENV: SESSION_MARKER_VALUE}


class SandboxSession:
    """Context manager: attach to (or bring up) the box, run one command, then release.

    Entering holds the project's lock only while the box is found or started; the
    command itself runs outside the lock, so any number of terminals can share the box.
    """

    def __init__(
        self,
        orchestrator: BoxOrchestrator,
        services: SandboxServices,
        observer: SandboxObserver | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._services = services
        self._observer = observer or SandboxObserver()
        self._box: RunningBox | None = None

    @property
    def box(self) -> RunningBox | None:
        return self._box

    def __enter__(self) -> SandboxSession:
        self._box = self._orchestrator.ensure()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._orchestrator.release()

    def run(self, command: Sequence[str], label: str) -> int:
        """Run ``command`` in the box, in the directory the CLI was started from."""
        if self._box is None:
            raise SandboxError("sandbox session is not started")
        self._observer.running(label, command)
        return self._services.terminal.run(
            self._box.id,
            command,
            workdir=str(self._orchestrator.workdir),
            environment=SESSION_ENVIRONMENT,
            secret_environment=self._orchestrator.session_environment(),
        )
