"""
ATLAS — Job Queue + Assignment Layer
=====================================
Durable queue with worker assignment, execution leases, and recovery.
Distinguishes "job accepted" from "job completed".
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid

from .job_contract import JobRecord, JobState
from .job_lifecycle import JobLifecycleManager, LifecycleError
from .job_store import JobStore


class QueueError(Exception):
    """Raised when a queue operation fails."""
    pass


class JobQueue:
    """Durable job queue with execution leases and recovery.

    Capabilities:
    - Durable submission with idempotency keys
    - Worker assignment with visibility timeout
    - Lease renewal
    - Abandoned-job recovery
    - Retry scheduling
    - Tenant-aware prioritization
    - Bounded concurrency
    - Cancellation signaling
    """

    def __init__(
        self,
        store: JobStore,
        lifecycle: JobLifecycleManager,
        default_lease_seconds: int = 30,
        max_concurrent_per_tenant: int = 3,
    ):
        self.store = store
        self.lifecycle = lifecycle
        self.default_lease_seconds = default_lease_seconds
        self.max_concurrent_per_tenant = max_concurrent_per_tenant

    # ── Submission ──────────────────────────────────────────────

    def enqueue(self, record: JobRecord) -> JobRecord:
        """Submit a job to the queue. Idempotent — duplicate keys return existing job."""
        # Check idempotency
        if record.contract.idempotency_key:
            existing = self.store.find_by_idempotency_key(
                record.contract.idempotency_key
            )
            if existing:
                # Return the existing job — submission is idempotent
                return existing

        # Persist the record first
        self.store.save(record)

        # Transition: CREATED → AUTHORIZED → QUEUED
        if record.current_state == JobState.CREATED.value:
            self.lifecycle.transition(record, JobState.AUTHORIZED,
                actor="job_queue", reason="enqueue: auto-authorized")
        if record.current_state == JobState.AUTHORIZED.value:
            self.lifecycle.transition(record, JobState.QUEUED,
                actor="job_queue", reason="enqueue: placed in queue")

        self.store.save(record)
        return record

    # ── Assignment ──────────────────────────────────────────────

    def assign(self, record: JobRecord, worker_id: str) -> JobRecord:
        """Assign a queued job to a worker. Sets execution lease."""
        if record.current_state != JobState.QUEUED.value:
            raise QueueError(
                f"Job {record.contract.job_id} is not QUEUED (current: {record.current_state}). "
                f"Cannot assign."
            )

        self.lifecycle.transition(record, JobState.ASSIGNED,
            actor=worker_id, reason="assign: worker claimed job")
        record.assigned_worker_id = worker_id
        record.lease_expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self.default_lease_seconds)
        ).isoformat()

        self.store.save(record)
        return record

    def start_execution(self, record: JobRecord, worker_id: str) -> JobRecord:
        """Worker signals that execution has begun."""
        if record.current_state != JobState.ASSIGNED.value:
            raise QueueError(
                f"Job {record.contract.job_id} is not ASSIGNED (current: {record.current_state})"
            )
        if record.assigned_worker_id != worker_id:
            raise QueueError(
                f"Worker '{worker_id}' does not hold the assignment for job {record.contract.job_id}"
            )

        self.lifecycle.transition(record, JobState.RUNNING,
            actor=worker_id, reason="start: execution began")
        record.execution_started_at = datetime.now(timezone.utc).isoformat()

        self.store.save(record)
        return record

    def complete_execution(self, record: JobRecord, worker_id: str) -> JobRecord:
        """Worker signals completion."""
        if record.current_state != JobState.RUNNING.value:
            raise QueueError(
                f"Job {record.contract.job_id} is not RUNNING (current: {record.current_state})"
            )

        self.lifecycle.transition(record, JobState.COMPLETED,
            actor=worker_id, reason="complete: execution finished")
        record.execution_completed_at = datetime.now(timezone.utc).isoformat()
        record.lease_expires_at = None

        self.store.save(record)
        return record

    # ── Lease management ────────────────────────────────────────

    def renew_lease(self, record: JobRecord, worker_id: str) -> JobRecord:
        """Renew the execution lease to prevent timeout."""
        if record.assigned_worker_id != worker_id:
            raise QueueError(f"Worker '{worker_id}' does not hold the lease.")

        record.lease_expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self.default_lease_seconds)
        ).isoformat()
        self.store.save(record)
        return record

    def is_lease_expired(self, record: JobRecord) -> bool:
        """Check if the job's execution lease has expired."""
        if not record.lease_expires_at:
            return False
        expires = datetime.fromisoformat(record.lease_expires_at)
        return datetime.now(timezone.utc) > expires

    def recover_abandoned_jobs(self) -> List[JobRecord]:
        """Find and recover jobs with expired leases. Returns recovered jobs."""
        recovered = []
        for job_id in self.store.list_jobs():
            record = self.store.load(job_id)
            if not record:
                continue
            # Only recover running/assigned jobs with expired leases
            if record.current_state in (JobState.RUNNING.value, JobState.ASSIGNED.value):
                if self.is_lease_expired(record):
                    try:
                        self.lifecycle.transition(record, JobState.RETRY_PENDING,
                            actor="job_queue", reason="recover: lease expired, retry pending")
                        record.lease_expires_at = None
                        record.assigned_worker_id = ""
                        self.store.save(record)
                        recovered.append(record)
                    except LifecycleError:
                        pass  # Job already recovered
        return recovered

    # ── Failure handling ────────────────────────────────────────

    def mark_failed(
        self, record: JobRecord, worker_id: str, terminal: bool = False
    ) -> JobRecord:
        """Mark a job as failed (retryable or terminal)."""
        target = JobState.FAILED_TERMINAL if terminal else JobState.FAILED_RETRYABLE
        self.lifecycle.transition(record, target,
            actor=worker_id, reason="failed: execution error")
        record.lease_expires_at = None

        if not terminal:
            record.retry_count += 1

        self.store.save(record)
        return record

    def schedule_retry(self, record: JobRecord) -> Optional[JobRecord]:
        """Schedule a retry if the job is retryable and has retries remaining."""
        if record.current_state not in (
            JobState.FAILED_RETRYABLE.value,
            JobState.RETRY_PENDING.value,
            JobState.RESULT_REJECTED.value,
        ):
            return None

        if record.retry_count > record.contract.max_retries:
            self.lifecycle.transition(record, JobState.FAILED_TERMINAL,
                actor="job_queue", reason=f"retry: exhausted ({record.retry_count}/{record.contract.max_retries})")
            self.store.save(record)
            return None

        # Transition: current → RETRY_PENDING → QUEUED
        self.lifecycle.transition(record, JobState.RETRY_PENDING,
            actor="job_queue", reason=f"retry: pending attempt {record.retry_count + 1}")
        self.lifecycle.transition(record, JobState.QUEUED,
            actor="job_queue", reason=f"retry: attempt {record.retry_count + 1}")
        record.lease_expires_at = None
        self.store.save(record)
        return record

    def cancel(self, record: JobRecord, actor: str, reason: str = "") -> JobRecord:
        """Cancel a queued or assigned job."""
        if record.current_state in (JobState.CREATED.value, JobState.AUTHORIZED.value,
                                     JobState.QUEUED.value, JobState.ASSIGNED.value):
            self.lifecycle.transition(record, JobState.CANCELLED,
                actor=actor, reason=f"cancel: {reason}")
        else:
            self.lifecycle.transition(record, JobState.CANCEL_REQUESTED,
                actor=actor, reason=f"cancel requested: {reason}")
        record.lease_expires_at = None
        self.store.save(record)
        return record

    # ── Queries ─────────────────────────────────────────────────

    def get_next_queued(self, tenant_id: Optional[str] = None) -> Optional[JobRecord]:
        """Get the next queued job for assignment."""
        for job_id in self.store.list_jobs(tenant_id):
            record = self.store.load(job_id)
            if record and record.current_state == JobState.QUEUED.value:
                # Check tenant concurrency
                if tenant_id:
                    running_count = self._count_running_for_tenant(tenant_id)
                    if running_count >= self.max_concurrent_per_tenant:
                        continue
                return record
        return None

    def _count_running_for_tenant(self, tenant_id: str) -> int:
        count = 0
        for job_id in self.store.list_jobs(tenant_id):
            record = self.store.load(job_id)
            if record and record.current_state in (
                JobState.ASSIGNED.value, JobState.RUNNING.value
            ):
                count += 1
        return count
