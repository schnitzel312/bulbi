"""What happens to findings (``[git] on_finding``): one :class:`FindingAction` per policy."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar

from bulbi.errors import GitSafetyError
from bulbi.gitsafety.findings import GitFinding
from bulbi.gitsafety.quarantine import QuarantineStore
from bulbi.spec import FindingPolicy

LEFT_IN_PLACE = "left in place"


@dataclass(frozen=True)
class ActionOutcome:
    """What was done about one finding."""

    finding: GitFinding
    done: str
    neutralised: bool


@dataclass(frozen=True)
class ActionResult:
    outcomes: tuple[ActionOutcome, ...] = ()
    record_id: str | None = None

    @property
    def unresolved(self) -> tuple[ActionOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.neutralised)


class FindingAction(ABC):
    """Applies one ``on_finding`` policy to a scan's findings."""

    policy: ClassVar[FindingPolicy]

    @abstractmethod
    def apply(self, findings: Sequence[GitFinding]) -> ActionResult:
        """Act on ``findings``; never deletes anything."""


class QuarantineAction(FindingAction):
    """Moves findings aside (or comments keys out) into one quarantine record."""

    policy = FindingPolicy.QUARANTINE

    def __init__(self, store: QuarantineStore) -> None:
        self._store = store

    def apply(self, findings: Sequence[GitFinding]) -> ActionResult:
        if not findings:
            return ActionResult()
        session = self._store.open()
        outcomes = []
        for finding in findings:
            try:
                outcomes.append(ActionOutcome(finding, finding.neutralise(session), True))
            except (OSError, shutil.Error, GitSafetyError) as exc:
                outcomes.append(ActionOutcome(finding, f"{LEFT_IN_PLACE}: {exc}", False))
        record = self._store.close(session)
        return ActionResult(tuple(outcomes), record.id if record else None)


class BlockAction(FindingAction):
    """Changes nothing; the findings stop the next attach."""

    policy = FindingPolicy.BLOCK

    def apply(self, findings: Sequence[GitFinding]) -> ActionResult:
        done = f'{LEFT_IN_PLACE} (on_finding = "{self.policy}")'
        return ActionResult(tuple(ActionOutcome(finding, done, False) for finding in findings))


ActionFactory = Callable[[QuarantineStore], FindingAction]


class FindingActions:
    """The action for each ``on_finding`` policy, registered in one place."""

    def __init__(self, factories: Mapping[FindingPolicy, ActionFactory]) -> None:
        self._factories = dict(factories)

    @classmethod
    def builtin(cls) -> FindingActions:
        return cls(
            {
                FindingPolicy.QUARANTINE: QuarantineAction,
                FindingPolicy.BLOCK: lambda _store: BlockAction(),
            }
        )

    def create(self, policy: FindingPolicy, store: QuarantineStore) -> FindingAction:
        return self._factories[policy](store)
