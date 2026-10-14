"""Project auto-detection and starter-spec rendering for ``bulbi init``."""

from __future__ import annotations

from bulbi.detection.base import DetectedProject, ProjectDetector
from bulbi.detection.go import GoDetector
from bulbi.detection.node import NodeDetector
from bulbi.detection.python import PythonDetector
from bulbi.detection.registry import DetectorRegistry
from bulbi.detection.rust import RustDetector
from bulbi.detection.starter_spec import StarterSpecRenderer

__all__ = [
    "DetectedProject",
    "DetectorRegistry",
    "GoDetector",
    "NodeDetector",
    "ProjectDetector",
    "PythonDetector",
    "RustDetector",
    "StarterSpecRenderer",
]
