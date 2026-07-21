"""
ATLAS — Job Lifecycle Manager
==============================
Authoritative state machine for durable job execution.
No component may write job state directly. All transitions pass through here.

Implements 17 states with explicit validated transitions.
Invalid transitions raise LifecycleError.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .job_contract import (
    JobState, JobRecord, StateTransition, ALLOWED_TRANSITIONS, _TERMINAL_STATES,
)


class LifecycleError(Exception):
    """Raised when an invalid state transition is attempted."""
    pass


class JobLifecycleManager:
    """The ONLY path to change a job's state.

    Usage:
        mgr = JobLifecycleManager()
        record = JobRecord(contract=contract)
        mgr.transition(record, JobState.AUTHORIZED, actor="auth-gate")
    """

    def __init__(self):
        self._enforce = True  # Always enforce; set False only in tests that bypass

    # ── Public API ──────────────────────────────────────────────

    def transition(
        self,
        record: JobRecord,
        target_state: JobState,
        actor: str = "",
        reason: str = "",
        correlation_id: str = "",
    ) -> StateTransition:
        """Transition a job to a new state. Raises LifecycleError if invalid.

        Returns the StateTransition record that was created.
        """
        current = self._resolve_current_state(record)

        # Guard: no transitions from terminal states
        if current in _TERMINAL_STATES and current != JobState.COMPLETED:
            raise LifecycleError(
                f"Cannot transition from terminal state '{current.value}'. "
                f"Terminal states: {[t.value for t in _TERMINAL_STATES]}"
            )
        # Special case: COMPLETED → RESULT_REJECTED is allowed
        if current == JobState.COMPLETED and target_state != JobState.RESULT_REJECTED:
            raise LifecycleError(
                f"From COMPLETED, only RESULT_REJECTED is allowed. "
                f"Requested: {target_state.value}"
            )

        # Guard: validate the transition is allowed
        allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
        if target_state not in allowed:
            allowed_names = [s.value for s in allowed]
            raise LifecycleError(
                f"Invalid transition: {current.value} → {target_state.value}. "
                f"Allowed from {current.value}: {allowed_names}"
            )

        # Create the transition record
        transition_record = StateTransition(
            transition_id=str(uuid.uuid4()),
            job_id=record.contract.job_id,
            previous_state=current.value,
            new_state=target_state.value,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            causation_id=str(uuid.uuid4()),
        )

        # Apply the transition
        record.current_state = target_state.value
        record.state_history.append(transition_record)
        record.updated_at = datetime.now(timezone.utc).isoformat()

        return transition_record

    def get_current_state(self, record: JobRecord) -> JobState:
        """Get the current state as a JobState enum."""
        return self._resolve_current_state(record)

    def is_terminal(self, record: JobRecord) -> bool:
        """Check if the job is in a terminal state."""
        return self._resolve_current_state(record) in _TERMINAL_STATES

    def is_live(self, record: JobRecord) -> bool:
        """Check if the job is live (can still transition to running/completed)."""
        return not self.is_terminal(record)

    def can_transition(self, record: JobRecord, target: JobState) -> bool:
        """Check if a transition would be valid without executing it."""
        current = self._resolve_current_state(record)
        return target in ALLOWED_TRANSITIONS.get(current, frozenset())

    def get_state_history(self, record: JobRecord) -> List[StateTransition]:
        """Return the full state transition history."""
        return list(record.state_history)

    def get_retry_count(self, record: JobRecord) -> int:
        """Return the number of retries that have occurred."""
        return record.retry_count

    # ── Helpers ─────────────────────────────────────────────────

    def _resolve_current_state(self, record: JobRecord) -> JobState:
        """Resolve the current state string to an enum value."""
        try:
            return JobState(record.current_state)
        except ValueError:
            raise LifecycleError(
                f"Unknown state: '{record.current_state}'. "
                f"Valid states: {[s.value for s in JobState]}"
            )
