"""Git configuration keys whose value makes git run a program (spec §1).

The registry is the single list Bulbi consults; to cover another key, add an
:class:`ExecKey` to :meth:`ExecConfigRegistry.builtin`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

ValueTest = Callable[[str], bool]
SHELL_PREFIX = "!"
_GIT_BOOLEANS = frozenset({"", "true", "false", "yes", "no", "on", "off", "1", "0"})


def any_value(value: str) -> bool:
    """The key runs whatever program its value names."""
    return True


def shell_command(value: str) -> bool:
    """Only values starting with ``!`` are shell commands (aliases, submodule update)."""
    return value.lstrip().startswith(SHELL_PREFIX)


def not_boolean(value: str) -> bool:
    """A boolean selects a built-in (e.g. ``core.fsmonitor = true``); anything else is a hook."""
    return value.strip().lower() not in _GIT_BOOLEANS


@dataclass(frozen=True)
class ExecKey:
    """A key pattern as ``git config --list`` prints it: section and name lower-case.

    ``*`` stands for a subsection (which may contain dots) or, for ``alias.*``, a name.
    """

    pattern: str
    runs: ValueTest = field(default=any_value, compare=False)

    def matches(self, key: str) -> bool:
        return fnmatchcase(key.lower(), self.pattern)


class ExecConfigRegistry:
    """Decides whether a ``key = value`` pair makes git execute something."""

    def __init__(self, keys: Iterable[ExecKey]) -> None:
        self._keys = tuple(keys)

    @property
    def patterns(self) -> tuple[str, ...]:
        return tuple(key.pattern for key in self._keys)

    def is_exec(self, key: str, value: str | None) -> bool:
        text = "" if value is None else value
        return any(rule.matches(key) and rule.runs(text) for rule in self._keys)

    @classmethod
    def builtin(cls) -> ExecConfigRegistry:
        return cls(
            [
                ExecKey("core.fsmonitor", not_boolean),
                ExecKey("core.hookspath"),
                ExecKey("core.sshcommand"),
                ExecKey("core.pager"),
                ExecKey("core.editor"),
                ExecKey("core.askpass"),
                ExecKey("core.gitproxy"),
                ExecKey("core.alternaterefscommand"),
                ExecKey("credential.helper"),
                ExecKey("credential.*.helper"),
                ExecKey("diff.external"),
                ExecKey("diff.*.textconv"),
                ExecKey("diff.*.command"),
                ExecKey("filter.*.clean"),
                ExecKey("filter.*.smudge"),
                ExecKey("filter.*.process"),
                ExecKey("merge.*.driver"),
                ExecKey("gpg.program"),
                ExecKey("gpg.*.program"),
                ExecKey("gpg.ssh.defaultkeycommand"),
                ExecKey("sequence.editor"),
                ExecKey("uploadpack.packobjectshook"),
                ExecKey("alias.*", shell_command),
                ExecKey("submodule.*.update", shell_command),
                ExecKey("pager.*"),
                ExecKey("interactive.difffilter"),
                ExecKey("remote.*.uploadpack"),
                ExecKey("remote.*.receivepack"),
                ExecKey("remote.*.vcs"),
                ExecKey("difftool.*.cmd"),
                ExecKey("difftool.*.path"),
                ExecKey("mergetool.*.cmd"),
                ExecKey("mergetool.*.path"),
                ExecKey("browser.*.cmd"),
                ExecKey("browser.*.path"),
                ExecKey("web.browser"),
                ExecKey("man.*.cmd"),
                ExecKey("man.*.path"),
                ExecKey("sendemail.sendmailcmd"),
                ExecKey("sendemail.smtpserver"),
                ExecKey("sendemail.tocmd"),
                ExecKey("sendemail.cccmd"),
                ExecKey("trailer.*.command"),
                ExecKey("trailer.*.cmd"),
                ExecKey("guitool.*.cmd"),
                ExecKey("instaweb.httpd"),
            ]
        )
