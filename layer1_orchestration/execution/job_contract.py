"""
ATLAS — Durable Job Contract
=============================
Stable data model for durable, recoverable, multi-agent job execution.
A job ID is a persistent identity, not a transient function return value.

This contract defines WHAT a job is. The lifecycle manager enforces HOW it moves.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Job state enum — authoritative lifecycle
# ═══════════════════════════════════════════════════════════════

class JobState(str, Enum):
    """Authoritative job lifecycle states. No component may write state directly."""

    # ── Primary lifecycle ──
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    QUEUED = "QUEUED"
    ASSIGNED = "ASSIGNED"
    RUNNING = "RUNNING"
    CHECKPOINTED = "CHECKPOINTED"
    COMPLETED = "COMPLETED"

    # ── Interruption / recovery ──
    PAUSED = "PAUSED"
    RETRY_PENDING = "RETRY_PENDING"

    # ── Failure ──
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    FAILED_TERMINAL = "FAILED_TERMINAL"

    # ── Cancellation ──
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"

    # ── Termination ──
    TIMED_OUT = "TIMED_OUT"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    STOPPED_BY_POLICY = "STOPPED_BY_POLICY"

    # ── Result ──
    RESULT_REJECTED = "RESULT_REJECTED"


# ═══════════════════════════════════════════════════════════════
# State groups
# ═══════════════════════════════════════════════════════════════

# States where the job is "live" (could transition to RUNNING or COMPLETED)
_LIVE_STATES = frozenset({
    JobState.CREATED, JobState.AUTHORIZED, JobState.QUEUED,
    JobState.ASSIGNED, JobState.RUNNING, JobState.CHECKPOINTED,
    JobState.PAUSED, JobState.RETRY_PENDING,
})

# Terminal states — no further transitions allowed
_TERMINAL_STATES = frozenset({
    JobState.COMPLETED, JobState.CANCELLED, JobState.FAILED_TERMINAL,
    JobState.TIMED_OUT, JobState.AUTHORIZATION_REVOKED,
    JobState.STOPPED_BY_POLICY, JobState.RESULT_REJECTED,
})


# ═══════════════════════════════════════════════════════════════
# Allowed state transitions
# ═══════════════════════════════════════════════════════════════

ALLOWED_TRANSITIONS: Dict[JobState, frozenset] = {
    JobState.CREATED: frozenset({JobState.AUTHORIZED, JobState.CANCELLED, JobState.TIMED_OUT}),
    JobState.AUTHORIZED: frozenset({JobState.QUEUED, JobState.AUTHORIZATION_REVOKED, JobState.CANCELLED}),
    JobState.QUEUED: frozenset({JobState.ASSIGNED, JobState.CANCELLED, JobState.TIMED_OUT}),
    JobState.ASSIGNED: frozenset({JobState.RUNNING, JobState.CANCELLED, JobState.TIMED_OUT, JobState.FAILED_RETRYABLE, JobState.FAILED_TERMINAL}),
    JobState.RUNNING: frozenset({
        JobState.CHECKPOINTED, JobState.COMPLETED,
        JobState.PAUSED, JobState.FAILED_RETRYABLE, JobState.FAILED_TERMINAL,
        JobState.CANCELLED, JobState.TIMED_OUT, JobState.AUTHORIZATION_REVOKED,
        JobState.STOPPED_BY_POLICY,
    }),
    JobState.CHECKPOINTED: frozenset({
        JobState.RUNNING, JobState.PAUSED,
        JobState.FAILED_RETRYABLE, JobState.FAILED_TERMINAL,
        JobState.CANCELLED, JobState.TIMED_OUT,
    }),
    JobState.COMPLETED: frozenset({JobState.RESULT_REJECTED}),  # Only validator can reject a completed result
    JobState.PAUSED: frozenset({JobState.RUNNING, JobState.CANCELLED, JobState.TIMED_OUT, JobState.FAILED_TERMINAL}),
    JobState.RETRY_PENDING: frozenset({JobState.QUEUED, JobState.FAILED_TERMINAL, JobState.CANCELLED}),
    JobState.FAILED_RETRYABLE: frozenset({JobState.RETRY_PENDING, JobState.FAILED_TERMINAL, JobState.CANCELLED}),
    JobState.FAILED_TERMINAL: frozenset(),  # Terminal
    JobState.CANCEL_REQUESTED: frozenset({JobState.CANCELLED, JobState.FAILED_TERMINAL}),
    JobState.CANCELLED: frozenset(),  # Terminal
    JobState.TIMED_OUT: frozenset({JobState.RETRY_PENDING}),  # Can retry after timeout
    JobState.AUTHORIZATION_REVOKED: frozenset(),  # Terminal
    JobState.STOPPED_BY_POLICY: frozenset(),  # Terminal
    JobState.RESULT_REJECTED: frozenset({JobState.RETRY_PENDING}),  # Can retry after rejection
}


# ═══════════════════════════════════════════════════════════════
# Validation decision
# ═══════════════════════════════════════════════════════════════

class ValidationDecision(str, Enum):
    """Independent validation verdict for a completed job result."""
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    INCOMPLETE = "INCOMPLETE"
    CONTRACT_MISMATCH = "CONTRACT_MISMATCH"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"


# ═══════════════════════════════════════════════════════════════
# Execution mode
# ═══════════════════════════════════════════════════════════════

class ExecutionMode(str, Enum):
    """How the job is executed."""
    DIRECT_SYNCHRONOUS = "DIRECT_SYNCHRONOUS"    # Immediate adapter call (perspective generation)
    DURABLE_ASYCHRONOUS = "DUABLE_ASYCHRONOUS"   # Full lifecycle through queue + workers
    MOCKED = "MOCKED"                            # Test harness


# ═══════════════════════════════════════════════════════════════
# Job contract
# ═══════════════════════════════════════════════════════════════

@dataclass
class JobContract:
    """Stable, durable job identity and execution contract.

    The job_id is the durable identity — returned immediately on submission,
    surviving restarts, crashes, and queue interruptions.
    """

    # ── Identity ──
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = ""
    mission_id: str = ""
    parent_finding_id: str = ""
    parent_chain_id: str = ""
    hypothesis_id: str = ""
    idempotency_key: str = ""  # Prevents duplicate submission

    # ── Work specification ──
    requested_action: str = ""
    action_type: str = ""
    source_engine: str = ""
    target_engine: str = ""
    target_asset: str = ""
    normalized_asset: str = ""
    authorized_scope: List[str] = field(default_factory=list)
    authorization_reference: str = ""

    # ── Execution configuration ──
    execution_mode: str = ExecutionMode.DURABLE_ASYCHRONOUS.value
    assigned_agent_roles: List[str] = field(default_factory=list)

    # ── Inputs ──
    input_evidence_references: List[str] = field(default_factory=list)
    expected_output_contract: Dict[str, Any] = field(default_factory=dict)

    # ── Budgets ──
    request_budget: int = 0
    time_budget_seconds: int = 300
    compute_budget: int = 0

    # ── Policies ──
    checkpoint_policy: str = "every_subtask"  # every_subtask | manual | interval:N
    retry_policy: str = "exponential_backoff"  # exponential_backoff | fixed | none
    max_retries: int = 3
    retry_delay_seconds: int = 5
    stop_conditions: List[str] = field(default_factory=list)

    # ── Timestamps ──
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None

    # ── Provenance ──
    provenance_context: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, **kwargs) -> JobContract:
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "mission_id": self.mission_id,
            "parent_finding_id": self.parent_finding_id,
            "parent_chain_id": self.parent_chain_id,
            "hypothesis_id": self.hypothesis_id,
            "idempotency_key": self.idempotency_key,
            "requested_action": self.requested_action,
            "action_type": self.action_type,
            "source_engine": self.source_engine,
            "target_engine": self.target_engine,
            "target_asset": self.target_asset,
            "normalized_asset": self.normalized_asset,
            "authorized_scope": self.authorized_scope,
            "authorization_reference": self.authorization_reference,
            "execution_mode": self.execution_mode,
            "assigned_agent_roles": self.assigned_agent_roles,
            "input_evidence_references": self.input_evidence_references,
            "expected_output_contract": self.expected_output_contract,
            "request_budget": self.request_budget,
            "time_budget_seconds": self.time_budget_seconds,
            "compute_budget": self.compute_budget,
            "checkpoint_policy": self.checkpoint_policy,
            "retry_policy": self.retry_policy,
            "max_retries": self.max_retries,
            "retry_delay_seconds": self.retry_delay_seconds,
            "stop_conditions": self.stop_conditions,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "provenance_context": self.provenance_context,
        }


# ═══════════════════════════════════════════════════════════════
# State transition record
# ═══════════════════════════════════════════════════════════════

@dataclass
class StateTransition:
    """A single state transition in the job's lifecycle history."""
    transition_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str = ""
    previous_state: str = ""
    new_state: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = ""
    reason: str = ""
    correlation_id: str = ""
    causation_id: str = ""

    def to_dict(self) -> dict:
        return {
            "transition_id": self.transition_id,
            "job_id": self.job_id,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
        }


# ═══════════════════════════════════════════════════════════════
# Job record — the full persisted job state
# ═══════════════════════════════════════════════════════════════

@dataclass
class JobRecord:
    """Complete persisted job state including contract, lifecycle, and execution data."""

    # ── Core ──
    contract: JobContract = field(default_factory=JobContract)
    current_state: str = JobState.CREATED.value

    # ── History ──
    state_history: List[StateTransition] = field(default_factory=list)

    # ── Execution ──
    assigned_worker_id: str = ""
    lease_expires_at: Optional[str] = None
    execution_started_at: Optional[str] = None
    execution_completed_at: Optional[str] = None
    requests_consumed: int = 0
    retry_count: int = 0

    # ── Checkpoints ──
    checkpoints: List[Dict[str, Any]] = field(default_factory=list)
    partial_outputs: List[Dict[str, Any]] = field(default_factory=list)

    # ── Result ──
    completion_result: Optional[Dict[str, Any]] = None
    validation_decision: Optional[str] = None
    validation_reason: str = ""
    validated_at: Optional[str] = None
    validated_by: str = ""

    # ── Evidence ──
    evidence_references: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)
    stop_events: List[Dict[str, Any]] = field(default_factory=list)

    # ── Metadata ──
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "contract": self.contract.to_dict(),
            "current_state": self.current_state,
            "state_history": [t.to_dict() for t in self.state_history],
            "assigned_worker_id": self.assigned_worker_id,
            "lease_expires_at": self.lease_expires_at,
            "execution_started_at": self.execution_started_at,
            "execution_completed_at": self.execution_completed_at,
            "requests_consumed": self.requests_consumed,
            "retry_count": self.retry_count,
            "checkpoints": self.checkpoints,
            "partial_outputs": self.partial_outputs,
            "completion_result": self.completion_result,
            "validation_decision": self.validation_decision,
            "validation_reason": self.validation_reason,
            "validated_at": self.validated_at,
            "validated_by": self.validated_by,
            "evidence_references": self.evidence_references,
            "error_messages": self.error_messages,
            "stop_events": self.stop_events,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> JobRecord:
        contract_data = data.get("contract", {})
        contract = JobContract(**contract_data)
        record = cls(contract=contract)
        record.current_state = data.get("current_state", JobState.CREATED.value)
        record.state_history = [
            StateTransition(**t) for t in data.get("state_history", [])
        ]
        record.assigned_worker_id = data.get("assigned_worker_id", "")
        record.lease_expires_at = data.get("lease_expires_at")
        record.execution_started_at = data.get("execution_started_at")
        record.execution_completed_at = data.get("execution_completed_at")
        record.requests_consumed = data.get("requests_consumed", 0)
        record.retry_count = data.get("retry_count", 0)
        record.checkpoints = data.get("checkpoints", [])
        record.partial_outputs = data.get("partial_outputs", [])
        record.completion_result = data.get("completion_result")
        record.validation_decision = data.get("validation_decision")
        record.validation_reason = data.get("validation_reason", "")
        record.validated_at = data.get("validated_at")
        record.validated_by = data.get("validated_by", "")
        record.evidence_references = data.get("evidence_references", [])
        record.error_messages = data.get("error_messages", [])
        record.stop_events = data.get("stop_events", [])
        record.created_at = data.get("created_at", "")
        record.updated_at = data.get("updated_at", "")
        return record
