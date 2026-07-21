"""
ATLAS — Worker Execution Contract + Checkpoint Manager
=======================================================
Workers claim, execute, and checkpoint durable jobs.
Never create downstream chain hops directly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .job_contract import JobRecord, JobState
from .job_lifecycle import JobLifecycleManager
from .job_store import JobStore
from .job_queue import JobQueue


# ═══════════════════════════════════════════════════════════════
# Worker contract
# ═══════════════════════════════════════════════════════════════

class BaseWorker(ABC):
    """Abstract worker that executes durable jobs.

    Workers must:
    - Claim queued jobs through the approved assignment path
    - Verify tenant, scope, and authorization
    - Record start time and emit progress events
    - Persist checkpoints and partial evidence
    - Respect budgets and stop conditions
    - Renew leases where required
    - Return structured completion or failure results
    - NEVER create downstream chain hops directly
    """

    def __init__(
        self,
        worker_id: str,
        queue: JobQueue,
        store: JobStore,
        lifecycle: JobLifecycleManager,
    ):
        self.worker_id = worker_id
        self.queue = queue
        self.store = store
        self.lifecycle = lifecycle

    # ── Public API ──────────────────────────────────────────────

    def claim_and_execute(self) -> Dict[str, Any]:
        """Claim the next queued job and execute it to completion.

        Returns a result dict with status and job data.
        """
        # 1. Claim a job
        record = self.queue.get_next_queued()
        if not record:
            return {"status": "no_jobs_available", "worker_id": self.worker_id}

        # 2. Assign
        try:
            record = self.queue.assign(record, self.worker_id)
        except Exception as e:
            return {"status": "assignment_failed", "error": str(e)}

        # 3. Verify authorization
        if not self._verify_authorization(record):
            self.queue.mark_failed(record, self.worker_id, terminal=True)
            return {"status": "authorization_failed", "job_id": record.contract.job_id}

        # 4. Start execution
        record = self.queue.start_execution(record, self.worker_id)

        # 5. Execute with checkpointing
        try:
            result = self._execute_with_checkpoints(record)
        except Exception as e:
            self.queue.mark_failed(record, self.worker_id, terminal=False)
            return {
                "status": "execution_failed",
                "job_id": record.contract.job_id,
                "error": str(e),
            }

        # 6. Store result
        record.completion_result = result
        record.evidence_references = result.get("evidence_references", [])
        self.queue.complete_execution(record, self.worker_id)

        return {
            "status": "completed",
            "job_id": record.contract.job_id,
            "result": result,
        }

    def execute_specific_job(self, job_id: str) -> Dict[str, Any]:
        """Execute a specific job by ID (used for recovery)."""
        record = self.store.load(job_id)
        if not record:
            return {"status": "not_found", "job_id": job_id}

        # Reload and start from current state
        record = self.queue.start_execution(record, self.worker_id)
        try:
            result = self._execute_with_checkpoints(record)
        except Exception as e:
            self.queue.mark_failed(record, self.worker_id, terminal=False)
            return {"status": "execution_failed", "job_id": job_id, "error": str(e)}

        record.completion_result = result
        self.queue.complete_execution(record, self.worker_id)

        return {"status": "completed", "job_id": job_id, "result": result}

    # ── Subclass hooks ──────────────────────────────────────────

    @abstractmethod
    def _do_work(self, record: JobRecord, context: Dict[str, Any]) -> Dict[str, Any]:
        """Perform the actual work. Subclasses implement engine-specific logic.

        Returns a result dict with at minimum:
        - evidence_references: list of evidence IDs
        - summary: human-readable summary
        - findings: list of finding dicts (tentative, not yet chain-advanced)
        """
        ...

    def _verify_authorization(self, record: JobRecord) -> bool:
        """Verify the job's authorization is still valid."""
        contract = record.contract
        if not contract.authorization_reference:
            return False
        if not contract.tenant_id:
            return False
        return True

    # ── Internal ────────────────────────────────────────────────

    def _execute_with_checkpoints(self, record: JobRecord) -> Dict[str, Any]:
        """Execute work with periodic checkpointing."""
        context = {
            "worker_id": self.worker_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        # Resume from last checkpoint if available
        if record.checkpoints:
            last_ckpt = record.checkpoints[-1]
            context.update(last_ckpt.get("context", {}))

        # Do the work
        result = self._do_work(record, context)

        # Auto-checkpoint after completion
        self._checkpoint(record, {
            "checkpoint_id": str(uuid.uuid4()),
            "type": "completion",
            "context": context,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "completed_subtasks": result.get("completed_subtasks", []),
            "evidence_collected": result.get("evidence_references", []),
            "budget_consumed": result.get("requests_consumed", 1),
        })

        return result

    def _checkpoint(self, record: JobRecord, ckpt_data: Dict[str, Any]) -> None:
        """Persist a checkpoint."""
        record.checkpoints.append(ckpt_data)
        record.requests_consumed = ckpt_data.get("budget_consumed",
            record.requests_consumed)
        self.store.save(record)


# ═══════════════════════════════════════════════════════════════
# Checkpoint Manager
# ═══════════════════════════════════════════════════════════════

class CheckpointManager:
    """Manages checkpoint persistence and recovery for durable jobs."""

    def __init__(self, store: JobStore, lifecycle: JobLifecycleManager):
        self.store = store
        self.lifecycle = lifecycle

    def save_checkpoint(
        self,
        record: JobRecord,
        actor: str,
        data: Dict[str, Any],
    ) -> JobRecord:
        """Save a checkpoint and optionally transition to CHECKPOINTED state."""
        checkpoint = {
            "checkpoint_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "data": data,
            "completed_subtasks": data.get("completed_subtasks", []),
            "pending_subtasks": data.get("pending_subtasks", []),
            "intermediate_findings": data.get("intermediate_findings", []),
            "evidence_collected": data.get("evidence_collected", []),
            "agent_messages": data.get("agent_messages", []),
            "budget_consumed": data.get("budget_consumed", 0),
            "remaining_budget": data.get("remaining_budget",
                record.contract.request_budget - record.requests_consumed),
            "plan_version": data.get("plan_version", 1),
            "authorization_status": data.get("authorization_status", "valid"),
            "unresolved_contradictions": data.get("unresolved_contradictions", []),
            "graph_mutations_pending": data.get("graph_mutations_pending", []),
        }
        record.checkpoints.append(checkpoint)
        record.requests_consumed += checkpoint["budget_consumed"]

        # Optionally transition to CHECKPOINTED state
        if record.current_state == JobState.RUNNING.value:
            self.lifecycle.transition(record, JobState.CHECKPOINTED,
                actor=actor, reason="checkpoint: execution state persisted")
        elif record.current_state == JobState.CHECKPOINTED.value:
            pass  # Already checkpointed, stay there

        self.store.save(record)
        return record

    def resume_from_checkpoint(
        self, record: JobRecord, actor: str
    ) -> Optional[JobRecord]:
        """Resume execution from the last checkpoint."""
        if not record.checkpoints:
            return None

        if record.current_state not in (
            JobState.CHECKPOINTED.value,
            JobState.PAUSED.value,
        ):
            return None

        self.lifecycle.transition(record, JobState.RUNNING,
            actor=actor, reason="resume: from checkpoint")

        self.store.save(record)
        return record

    def get_latest_checkpoint(self, record: JobRecord) -> Optional[Dict[str, Any]]:
        """Get the most recent checkpoint."""
        if not record.checkpoints:
            return None
        return record.checkpoints[-1]

    def can_recover(self, record: JobRecord) -> bool:
        """Check if a job can be recovered from checkpoints."""
        return bool(record.checkpoints) and record.current_state in (
            JobState.CHECKPOINTED.value,
            JobState.PAUSED.value,
            JobState.FAILED_RETRYABLE.value,
        )
