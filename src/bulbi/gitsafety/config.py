"""Reading git config files one at a time, and neutralising a key in one.

Files are read by the host's own ``git config --file`` (without following includes),
so Bulbi sees exactly what git would. Includes are chased by the caller, which keeps
every finding pointing at the file that really holds the key.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from bulbi.errors import GitSafetyError
from bulbi.gitsafety.hostgit import HostGit
from bulbi.paths import expand_home

INCLUDE_PATH_KEY = "include.path"
_INCLUDE_IF_PREFIX = "includeif."
_PATH_SUFFIX = ".path"
COMMENT_PREFIX = "# bulbi-quarantined: "
_HEADER = re.compile(r'^\s*\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')
_KEY = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=|$|[#;])")
_ESCAPE = re.compile(r"\\(.)")


@dataclass(frozen=True)
class ConfigEntry:
    """One ``key = value`` line, with the key as ``git config --list`` prints it."""

    key: str
    value: str | None

    @property
    def is_include(self) -> bool:
        key = self.key.lower()
        return key == INCLUDE_PATH_KEY or (
            key.startswith(_INCLUDE_IF_PREFIX) and key.endswith(_PATH_SUFFIX)
        )


class ConfigUnreadableError(GitSafetyError):
    """git cannot parse a config file."""


class GitConfigReader(ABC):
    """Lists the entries of one config file, includes not followed."""

    @abstractmethod
    def read(self, path: Path) -> tuple[ConfigEntry, ...]:
        """Every entry of ``path``; raises :class:`ConfigUnreadableError` if git cannot."""


class HostGitConfigReader(GitConfigReader):
    """``git config --file <path> --list --null`` with the host's git."""

    def __init__(self, git: HostGit | None = None) -> None:
        self._git = git or HostGit()

    def read(self, path: Path) -> tuple[ConfigEntry, ...]:
        result = self._git.run(["config", "--file", str(path), "--list", "--null"])
        if result.returncode != 0:
            raise ConfigUnreadableError(f"git cannot read {path}: {result.stderr.strip()}")
        entries = []
        for item in result.stdout.split("\0"):
            if item:
                key, newline, value = item.partition("\n")
                entries.append(ConfigEntry(key, value if newline else None))
        return tuple(entries)


def include_target(entry: ConfigEntry, config_file: Path, home: Path) -> Path | None:
    """The file an ``include.path`` / ``includeIf.*.path`` entry names, as git resolves it.

    Conditions are ignored on purpose: every file git *might* include is checked.
    """
    if not entry.is_include or not entry.value:
        return None
    path = Path(expand_home(entry.value, home))
    return path if path.is_absolute() else config_file.parent / path


class GitConfigEditor:
    """Comments a key out of a config file, keeping the values that were already trusted.

    Every line that sets the key is prefixed with ``# bulbi-quarantined:``. The result
    is re-read with git: should git still see an untrusted value (a line this editor
    could not attribute), the key is removed with ``git config --unset-all`` instead.
    Trusted values are then added back.
    """

    def __init__(self, reader: GitConfigReader, git: HostGit | None = None) -> None:
        self._reader = reader
        self._git = git or HostGit()

    def neutralise(self, path: Path, key: str, trusted: Sequence[str | None] = ()) -> None:
        path.write_text(commented_out(path.read_text(), key))
        if self._untrusted(path, key, ()):
            self._git_config(path, "--unset-all", key)
        for value in trusted:
            self._git_config(path, "--add", key, "true" if value is None else value)
        if self._untrusted(path, key, trusted):
            raise GitSafetyError(f"could not remove {key} from {path}")

    def _untrusted(self, path: Path, key: str, trusted: Sequence[str | None]) -> bool:
        target = key.lower()
        return any(
            entry.key.lower() == target and entry.value not in trusted
            for entry in self._reader.read(path)
        )

    def _git_config(self, path: Path, *args: str) -> None:
        result = self._git.run(["config", "--file", str(path), *args])
        if result.returncode not in (0, 5):  # 5: nothing to unset.
            raise GitSafetyError(f"git config failed on {path}: {result.stderr.strip()}")


def commented_out(text: str, key: str) -> str:
    """``text`` (a git config file) with every line setting ``key`` commented out."""
    return "".join(_commented_lines(text.splitlines(keepends=True), key.lower()))


def _commented_lines(lines: Sequence[str], key: str) -> Iterator[str]:
    section: str | None = None
    continuing = False
    for line in lines:
        body = line.rstrip("\r\n")
        if continuing:
            continuing = _continues(body)
            yield COMMENT_PREFIX + line
            continue
        header = _HEADER.match(body)
        if header:
            section = _section_name(header.group(1), header.group(2))
            rest = body[header.end() :]
            if _full_key(section, rest) == key:
                continuing = _continues(body)
                yield body[: header.end()] + "\n" + COMMENT_PREFIX + rest.lstrip() + "\n"
                continue
            yield line
            continue
        if section is not None and _full_key(section, body) == key:
            continuing = _continues(body)
            yield COMMENT_PREFIX + line
            continue
        yield line


def _section_name(name: str, subsection: str | None) -> str:
    if subsection is not None:
        unescaped = _ESCAPE.sub(r"\1", subsection)
        return f"{name.lower()}.{unescaped}"
    # Legacy ``[section.subsection]``: git lower-cases the whole thing.
    return name.lower()


def _full_key(section: str, text: str) -> str | None:
    match = _KEY.match(text)
    return f"{section}.{match.group(1).lower()}".lower() if match else None


def _continues(body: str) -> bool:
    trailing = len(body) - len(body.rstrip("\\"))
    return trailing % 2 == 1
