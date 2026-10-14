"""The container entrypoint script, which runs the spec's setup commands once."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from bulbi.constants import CONTAINER_HOME, CONTAINER_WORKSPACE

SETUP_MARKER_PATH = f"{CONTAINER_HOME}/.bulbi-setup-done"
SETUP_LOCK_PATH = f"{CONTAINER_HOME}/.bulbi-setup.lock"
PROJECT_DIR_ENV = "BULBI_PROJECT_DIR"
IDLE_WATCHER_PATH = "/usr/local/bin/bulbi-idle-watcher"
SESSION_MARKER_ENV = "BULBI_EXEC"
SESSION_MARKER_VALUE = "session"
IDLE_CHECK_SECONDS = 30


@dataclass(frozen=True)
class EntrypointScript:
    """Runs ``setup_commands`` once per box, then execs the session's command.

    Setup runs in the main checkout (``$BULBI_PROJECT_DIR``), in a subshell so the
    session keeps the working directory ``docker exec -w`` gave it, and under a lock so
    two sessions starting at once do not both run it. It is deferred to container start
    because the project is only bind-mounted at run time.
    """

    setup_commands: Sequence[str]

    def render(self) -> str:
        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# Run setup commands on first start (skip if already done).",
            f'MARKER="{SETUP_MARKER_PATH}"',
            'if [ ! -f "$MARKER" ]; then',
            f'    exec 9>"{SETUP_LOCK_PATH}"',
            "    flock 9",
            '    if [ ! -f "$MARKER" ]; then',
            f'        (cd "${{{PROJECT_DIR_ENV}:-{CONTAINER_WORKSPACE}}}"',
            *(f"         {command}" for command in self.setup_commands),
            "        )",
            '        touch "$MARKER"',
            "    fi",
            "    exec 9>&-",
            "fi",
            "",
            "# Execute the requested command.",
            'exec "$@"',
            "",
        ]
        return "\n".join(lines)


@dataclass(frozen=True)
class IdleWatcherScript:
    """The box's PID 1: exits (stopping the box) after ``$1`` seconds without sessions.

    A session is any process carrying ``BULBI_EXEC=session`` in its environment (every
    ``docker exec`` session sets it and its children inherit it). ``0`` disables the
    watcher; the CLI then stops the box when the last session ends (spec §8.3).
    """

    def render(self) -> str:
        lines = [
            "#!/bin/bash",
            "trap 'exit 0' TERM INT",
            'timeout="${1:-0}"',
            f"interval={IDLE_CHECK_SECONDS}",
            'if [ "$timeout" -gt 0 ] && [ "$timeout" -lt "$interval" ]; then',
            '    interval="$timeout"',
            "fi",
            "idle=0",
            "while true; do",
            '    sleep "$interval" & wait $!',
            '    if [ "$timeout" -le 0 ]; then continue; fi',
            f"    marker='{SESSION_MARKER_ENV}={SESSION_MARKER_VALUE}'",
            '    if grep -qsxz "$marker" /proc/[0-9]*/environ; then',
            "        idle=0",
            "    else",
            "        idle=$((idle + interval))",
            '        if [ "$idle" -ge "$timeout" ]; then exit 0; fi',
            "    fi",
            "done",
            "",
        ]
        return "\n".join(lines)
