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
ATTACH_MARKER_PATH = f"{CONTAINER_HOME}/.bulbi-attached"
ATTACH_GRACE_SECONDS = 60


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

    A session is a ``docker exec`` process carrying ``BULBI_EXEC=session``. Only session
    *leaders* count (PPID 0 inside the container), so a process an agent backgrounds,
    which inherits the variable, cannot keep the box alive forever. Before exiting, the
    watcher re-checks for sessions and honours a recent attach marker (touched by the
    CLI under its lock right before a new session starts), closing the race between its
    scan and a session that is just attaching. ``0`` disables the watcher; the CLI then
    stops the box when the last session ends (spec §8.3).
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
            f"marker='{SESSION_MARKER_ENV}={SESSION_MARKER_VALUE}'",
            "",
            "has_session() {",
            "    local proc stat rest",
            "    for proc in /proc/[0-9]*; do",
            '        read -r stat < "$proc/stat" 2>/dev/null || continue',
            '        rest="${stat##*) }"',
            "        set -- $rest",
            '        [ "$2" = 0 ] || continue',
            '        grep -qsxz "$marker" "$proc/environ" && return 0',
            "    done",
            "    return 1",
            "}",
            "",
            "recently_attached() {",
            "    local touched",
            f'    touched=$(stat -c %Y "{ATTACH_MARKER_PATH}" 2>/dev/null) || return 1',
            f"    [ $(( $(date +%s) - touched )) -lt {ATTACH_GRACE_SECONDS} ]",
            "}",
            "",
            "idle=0",
            "while true; do",
            '    sleep "$interval" & wait $!',
            '    if [ "$timeout" -le 0 ]; then continue; fi',
            "    if has_session; then",
            "        idle=0",
            "        continue",
            "    fi",
            "    idle=$((idle + interval))",
            '    if [ "$idle" -ge "$timeout" ]; then',
            "        if has_session || recently_attached; then",
            "            idle=0",
            "            continue",
            "        fi",
            "        exit 0",
            "    fi",
            "done",
            "",
        ]
        return "\n".join(lines)
