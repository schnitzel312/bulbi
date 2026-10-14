"""Keeping the Linux host relay alive as long as the box, not just one CLI process.

A box outlives the terminal that created it (spec §8), so the relay for ``host:`` rules
runs as a detached ``python -m bulbi.gateway.relay`` process, tracked by a pid file in
the project's ``.bulbi/`` directory and stopped together with the gateway.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

PID_FILENAME = "relay.pid"
LOG_FILENAME = "relay.log"
RELAY_MODULE = "bulbi.gateway.relay"


class RelayLauncher(ABC):
    """Starts and stops the host relay for one box."""

    @abstractmethod
    def ensure(self, bind_host: str, ports: Sequence[int], allowed_source: str) -> None:
        """Make sure a relay with exactly this configuration is running."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the relay if one is running."""


class ProcessRelayLauncher(RelayLauncher):
    """Runs the relay as a detached process recorded in ``<state_dir>/relay.pid``."""

    def __init__(
        self,
        state_dir: Path,
        popen: Callable[..., Any] = subprocess.Popen,
        signal_process: Callable[[int, int], None] = os.kill,
        python: str = sys.executable,
    ) -> None:
        self._state_dir = state_dir
        self._popen = popen
        self._signal = signal_process
        self._python = python

    @property
    def _pid_file(self) -> Path:
        return self._state_dir / PID_FILENAME

    def ensure(self, bind_host: str, ports: Sequence[int], allowed_source: str) -> None:
        argv = [
            self._python, "-m", RELAY_MODULE, "--bind", bind_host, "--source", allowed_source,
            "--ports", ",".join(str(port) for port in sorted(ports)),
        ]  # fmt: skip
        recorded = self._recorded()
        if recorded is not None and recorded["argv"] == argv and self._alive(recorded["pid"]):
            return
        self.stop()
        self._state_dir.mkdir(parents=True, exist_ok=True)
        with (self._state_dir / LOG_FILENAME).open("a") as log:
            process = self._popen(
                argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True
            )
        self._pid_file.write_text(json.dumps({"pid": process.pid, "argv": argv}))

    def stop(self) -> None:
        recorded = self._recorded()
        if recorded is not None and self._alive(recorded["pid"]):
            self._signal(recorded["pid"], signal.SIGTERM)
        self._pid_file.unlink(missing_ok=True)

    def _recorded(self) -> dict[str, Any] | None:
        try:
            data = json.loads(self._pid_file.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and isinstance(data.get("pid"), int) else None

    def _alive(self, pid: int) -> bool:
        try:
            self._signal(pid, 0)
        except (ProcessLookupError, PermissionError):
            return False
        return True
