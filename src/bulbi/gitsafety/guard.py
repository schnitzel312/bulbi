"""``GitGuard``: records the baseline, scans, acts on findings and audits them.

The one object the sandbox, ``bulbi git-scan`` and ``bulbi git-restore`` talk to.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from bulbi.gateway.audit import AuditLogWriter, LogEntry, audit_log_path, timestamp
from bulbi.gitsafety.actions import ActionOutcome, FindingAction, FindingActions
from bulbi.gitsafety.baseline import BaselineStore, GitBaseline, baseline_path
from bulbi.gitsafety.config import GitConfigEditor, HostGitConfigReader
from bulbi.gitsafety.exec_keys import ExecConfigRegistry
from bulbi.gitsafety.findings import GitFinding
from bulbi.gitsafety.hostgit import HostGit
from bulbi.gitsafety.inventory import Clock, GitInventory
from bulbi.gitsafety.quarantine import QuarantineRecord, QuarantineStore
from bulbi.gitsafety.scanner import GitSafetyScanner
from bulbi.spec import FindingPolicy, GitSpec

GIT_AUDIT_METHOD = "GIT"


@dataclass(frozen=True)
class GitSafetyReport:
    """One scan: what was found, what was done, and whether an attach may proceed."""

    findings: tuple[GitFinding, ...]
    outcomes: tuple[ActionOutcome, ...]
    policy: FindingPolicy
    record_id: str | None = None
    complete: bool = True
    budget: str = ""

    @property
    def clean(self) -> bool:
        return not self.findings and self.complete

    @property
    def unresolved(self) -> tuple[ActionOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.neutralised)

    @property
    def blocks_attach(self) -> bool:
        """Findings left in place, or a scan that ran out of time, stop an attach."""
        return bool(self.unresolved) or not self.complete

    def refusal(self) -> str:
        """Why an attach is refused (only meaningful when :attr:`blocks_attach`)."""
        if not self.complete:
            return (
                f"the git safety scan did not finish within [git] scan_budget = "
                f"{self.budget!r}; refusing to attach. Raise scan_budget or add large "
                "directories to [git] skip."
            )
        return (
            f"{len(self.unresolved)} dangerous git change(s) are still in place (listed "
            "above); refusing to attach. Remove them yourself, or set [git] on_finding = "
            '"quarantine" and run `bulbi git-scan`.'
        )


class GitAuditLog:
    """Appends findings to the network audit log with ``method = "GIT"`` (spec §2.4)."""

    def __init__(self, writer: AuditLogWriter) -> None:
        self._writer = writer

    def record(self, outcomes: Sequence[ActionOutcome], policy: FindingPolicy) -> None:
        for outcome in outcomes:
            finding = outcome.finding
            self._writer.write(
                LogEntry(
                    timestamp=timestamp(),
                    domain=str(finding.path),
                    action=str(policy),
                    method=GIT_AUDIT_METHOD,
                    url=finding.detail,
                    reason=finding.reason.value,
                    rule=outcome.done,
                )
            )


class GitGuard:
    """Git safety for one project and profile (spec §2)."""

    def __init__(  # noqa: PLR0913 - every collaborator is injected
        self,
        *,
        settings: GitSpec,
        baselines: BaselineStore,
        inventory: GitInventory,
        scanner: GitSafetyScanner,
        action: FindingAction,
        quarantine: QuarantineStore,
        audit: GitAuditLog,
    ) -> None:
        self._settings = settings
        self._baselines = baselines
        self._inventory = inventory
        self._scanner = scanner
        self._action = action
        self.quarantine = quarantine
        self._audit = audit

    @classmethod
    def for_project(  # noqa: PLR0913 - keyword knobs with defaults
        cls,
        settings: GitSpec,
        project_root: Path,
        state_dir: Path,
        profile: str | None = None,
        *,
        git: HostGit | None = None,
        home: Path | None = None,
        clock: Clock = time.monotonic,
    ) -> GitGuard:
        host_git = git or HostGit()
        reader = HostGitConfigReader(host_git)
        registry = ExecConfigRegistry.builtin()
        inventory = GitInventory(
            reader,
            skip=settings.skip,
            home=home,
            budget=settings.scan_budget_seconds(),
            clock=clock,
        )
        quarantine = QuarantineStore(
            state_dir, project_root, lambda: GitConfigEditor(reader, host_git)
        )
        return cls(
            settings=settings,
            baselines=BaselineStore(baseline_path(state_dir, profile), registry),
            inventory=inventory,
            scanner=GitSafetyScanner(inventory, registry),
            action=FindingActions.builtin().create(settings.on_finding, quarantine),
            quarantine=quarantine,
            audit=GitAuditLog(AuditLogWriter(audit_log_path(project_root))),
        )

    @property
    def has_baseline(self) -> bool:
        return self._baselines.path.is_file()

    def record_baseline(
        self, roots: Sequence[Path], protected: Sequence[Path], common_dir: Path | None
    ) -> GitBaseline:
        """Snapshot what the box is about to be able to write (at box creation)."""
        snapshot = self._inventory.take(roots, common_dir)
        baseline = GitBaseline(tuple(roots), tuple(protected), common_dir, snapshot)
        self._baselines.save(baseline)
        return baseline

    def scan(self) -> GitSafetyReport | None:
        """Scan, apply ``on_finding`` and audit; ``None`` when no box has a baseline yet."""
        baseline = self._baselines.load()
        if baseline is None:
            return None
        result = self._scanner.scan(baseline)
        acted = self._action.apply(result.findings)
        self._audit.record(acted.outcomes, self._action.policy)
        return GitSafetyReport(
            findings=result.findings,
            outcomes=acted.outcomes,
            policy=self._action.policy,
            record_id=acted.record_id,
            complete=result.complete,
            budget=self._settings.scan_budget,
        )

    def restore(self, record_id: str) -> QuarantineRecord:
        """Put a record back and trust what was restored from now on."""
        record = self.quarantine.restore(record_id)
        baseline = self._baselines.load()
        if baseline is not None:
            fresh = self._inventory.take(baseline.roots, baseline.common_dir)
            restored = [item.original for item in record.items]
            self._baselines.save(baseline.accepting(fresh, restored))
        return record
