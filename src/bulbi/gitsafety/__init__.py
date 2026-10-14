"""Git safety: stop agents from planting code that runs on the host via git.

See docs/specs/git-safety.md. :class:`GitGuard` scans the mounted checkouts for git
metadata the agent could use (guarded mode); :class:`GitMode` decides how the box sees
the project's git metadata at all (guarded or isolated).
"""

from __future__ import annotations

from bulbi.gitsafety.actions import BlockAction, FindingAction, FindingActions, QuarantineAction
from bulbi.gitsafety.exec_keys import ExecConfigRegistry, ExecKey
from bulbi.gitsafety.findings import (
    ExecConfigFinding,
    FindingReason,
    ForeignPointerFinding,
    GitFinding,
    HookChangedFinding,
    NewGitDirFinding,
)
from bulbi.gitsafety.guard import GitGuard, GitSafetyReport
from bulbi.gitsafety.scanner import GitSafetyScanner, ScanResult

__all__ = [
    "BlockAction",
    "ExecConfigFinding",
    "ExecConfigRegistry",
    "ExecKey",
    "FindingAction",
    "FindingActions",
    "FindingReason",
    "ForeignPointerFinding",
    "GitFinding",
    "GitGuard",
    "GitSafetyReport",
    "GitSafetyScanner",
    "HookChangedFinding",
    "NewGitDirFinding",
    "QuarantineAction",
    "ScanResult",
]
