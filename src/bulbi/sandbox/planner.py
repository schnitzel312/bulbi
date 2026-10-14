"""Deciding what to do with a project's box (spec §8.2): a small, pure state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from bulbi.container.manager import ContainerState
from bulbi.errors import SandboxError


class BoxPlan(StrEnum):
    CREATE = "create"  # No box: full start sequence.
    ATTACH = "attach"  # Running with the current spec: just add a session.
    START = "start"  # Stopped (or its gateway stopped), same spec: start it again.
    RECREATE = "recreate"  # Outdated spec, no sessions: replace box and gateway.


class OutdatedBoxError(SandboxError):
    """The spec changed while sessions still use the old box."""


@dataclass(frozen=True)
class BoxObservation:
    """What exists for a box key right now."""

    box: ContainerState | None
    gateway: ContainerState | None
    active_sessions: int = 0


class BoxPlanner:
    """Maps an observation and the current spec hash to a :class:`BoxPlan`."""

    def plan(self, observation: BoxObservation, spec_hash: str) -> BoxPlan:
        box, gateway, sessions = observation.box, observation.gateway, observation.active_sessions
        if box is None:
            return BoxPlan.CREATE
        if box.spec_hash != spec_hash:
            if sessions:
                raise OutdatedBoxError(
                    f"box is running an older spec with {sessions} active "
                    f"{'session' if sessions == 1 else 'sessions'}; finish them or run "
                    "`bulbi restart`"
                )
            return BoxPlan.RECREATE
        if gateway is None:
            # The box shares the gateway's network namespace; without it, start over.
            return BoxPlan.RECREATE
        if box.running and gateway.running:
            return BoxPlan.ATTACH
        if box.running and sessions:
            raise SandboxError(
                f"the box's network gateway stopped while {sessions} sessions are active; "
                "finish them or run `bulbi restart`"
            )
        return BoxPlan.START
