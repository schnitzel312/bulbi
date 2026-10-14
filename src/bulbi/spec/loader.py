"""Locating and loading the spec from a project directory."""

from __future__ import annotations

import tomllib
from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from bulbi.constants import SPEC_FILENAME
from bulbi.errors import SpecError
from bulbi.spec.models import BulbiSpec
from bulbi.spec.parser import RawTable, SpecParser

PYPROJECT_FILENAME = "pyproject.toml"


class SpecSource(ABC):
    """One place a spec may live inside a project."""

    @abstractmethod
    def read(self, project_root: Path) -> RawTable | None:
        """Return the raw spec table, or ``None`` if this source has no spec."""

    @staticmethod
    def _load_toml(path: Path) -> RawTable:
        try:
            with path.open("rb") as handle:
                return tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise SpecError(f"invalid TOML in {path}: {exc}") from exc


class BulbiTomlSource(SpecSource):
    """A standalone ``bulbi.toml`` at the project root."""

    def read(self, project_root: Path) -> RawTable | None:
        path = project_root / SPEC_FILENAME
        return self._load_toml(path) if path.is_file() else None


class PyprojectSource(SpecSource):
    """A ``[tool.bulbi]`` table inside ``pyproject.toml``."""

    def read(self, project_root: Path) -> RawTable | None:
        path = project_root / PYPROJECT_FILENAME
        if not path.is_file():
            return None
        table: RawTable | None = self._load_toml(path).get("tool", {}).get("bulbi")
        return table


class SpecLoader:
    """Loads the spec from the first source that provides one."""

    def __init__(
        self,
        sources: Sequence[SpecSource] | None = None,
        parser: SpecParser | None = None,
    ) -> None:
        self._sources = sources or (BulbiTomlSource(), PyprojectSource())
        self._parser = parser or SpecParser()

    def load(self, project_root: Path) -> BulbiSpec:
        for source in self._sources:
            raw = source.read(project_root)
            if raw is not None:
                return self._parser.parse(raw)
        raise SpecError(f"no {SPEC_FILENAME} found in {project_root}")
