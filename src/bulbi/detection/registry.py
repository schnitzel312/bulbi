"""Picks the detector that recognises a project."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from bulbi.detection.base import COMMON_TOOLS, DetectedProject, ProjectDetector
from bulbi.detection.go import GoDetector
from bulbi.detection.node import NodeDetector
from bulbi.detection.python import PythonDetector
from bulbi.detection.rust import RustDetector


class DetectorRegistry:
    """Tries detectors in priority order; the first match describes the project."""

    def __init__(self, detectors: Sequence[ProjectDetector]) -> None:
        self._detectors = tuple(detectors)

    @classmethod
    def builtin(cls) -> DetectorRegistry:
        return cls([PythonDetector(), NodeDetector(), RustDetector(), GoDetector()])

    def detect(self, project_root: Path) -> DetectedProject:
        for detector in self._detectors:
            if detector.matches(project_root):
                return detector.detect(project_root)
        return DetectedProject(name=project_root.resolve().name, language=None, tools=COMMON_TOOLS)
