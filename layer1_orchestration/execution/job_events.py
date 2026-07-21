"""
ATLAS — Job Event Model
========================
Durable lifecycle events for job execution.
Events must be persisted before downstream consumers act on them.
"""
from __future__ import annotations

import json
import os
import fcntl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Event types
# ═══════════════════════════════════════════════════════════════

class JobEventType(str, Enum):
    """Durable job lifecycle event types."""

    JOB_CREATED = "JOB_CREATED"
    JOB_AUTHORIZED="JOB_..."
    JOB_QUEUED = "JOB_QUEUED"
    JOB_ASSIGNED = "JOB_ASSIGNED"
    JOB_STARTED = "JOB_STARTED"
    JOB_PROGRESS_UPDATED = "JOB_PROGRESS_UPDATED"
    JOB_CHECKPOINTED = "JOB_CHECKPOINTED"
    JOB_PAUSED = "JOB_PAUSED"
    JOB_RESUMED = "JOB_RESUMED"
    JOB_RETRY_SCHEDULED = "JOB_RETRY_SCHEDULED"
    JOB_COMPLETED = "JOB_COMPLETED"
    JOB_FAILED = "JOB_FAILED"
    JOB_CANCELLED = "JOB_CANCELLED"
    JOB_RESULT_VALIDATED = "JOB_RESULT_VALIDATED"
    JOB_RESULT_REJECTED = "JOB_RESULT_REJECTED"
    JOB_LEASE_EXPIRED = "JOB_LEASE_EXPIRED"
    JOB_RECOVERED = "JOB_RECOVERED"


# ═══════════════════════════════════════════════════════════════
# Event record
# ═══════════════════════════════════════════════════════════════

@dataclass
class JobEvent:
    """A single durable job lifecycle event."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""
    job_id: str = ""
    tenant_id: str = ""
    mission_id: str = ""
    previous_state: str = ""
    new_state: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = ""
    correlation_id: str = ""
    causation_id: str = ""
    provenance: str = ""
    payload_version: str = "1.0"
    payload: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, **kwargs) -> JobEvent:
        if "event_id" not in kwargs:
            kwargs["event_id"] = str(uuid.uuid4())
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "mission_id": self.mission_id,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "provenance": self.provenance,
            "payload_version": self.payload_version,
            "payload": self.payload,
        }


# ═══════════════════════════════════════════════════════════════
# Event emitter
# ═══════════════════════════════════════════════════════════════

class JobEventEmitter:
    """Emits durable job events and persists them before consumer notification."""

    def __init__(self, events_filepath: str = "/tmp/atlas_jobs/events.jsonl"):
        self.events_filepath = events_filepath
        os.makedirs(os.path.dirname(events_filepath), exist_ok=True)

    def emit(self, event: JobEvent) -> JobEvent:
        """Emit and persist a job event."""
        with open(self.events_filepath, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                json.dump(event.to_dict(), f)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        return event

    def read_events(self, job_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Read all events, optionally filtered by job_id."""
        if not os.path.exists(self.events_filepath):
            return []

        events = []
        with open(self.events_filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                    if job_id is None or evt.get("job_id") == job_id:
                        events.append(evt)
                except json.JSONDecodeError:
                    continue
        return events

    def emit_from_transition(
        self,
        record,
        transition,
        actor: str = "",
    ) -> JobEvent:
        """Emit an event derived from a state transition."""
        event_type_map = {
            "CREATED": JobEventType.JOB_CREATED,
            "AUTHORIZED": JobEventType.JOB_AUTHORIZED,
            "QUEUED": JobEventType.JOB_QUEUED,
            "ASSIGNED": JobEventType.JOB_ASSIGNED,
            "RUNNING": JobEventType.JOB_STARTED,
            "CHECKPOINTED": JobEventType.JOB_CHECKPOINTED,
            "PAUSED": JobEventType.JOB_PAUSED,
            "COMPLETED": JobEventType.JOB_COMPLETED,
            "FAILED_RETRYABLE": JobEventType.JOB_FAILED,
            "FAILED_TERMINAL": JobEventType.JOB_FAILED,
            "CANCELLED": JobEventType.JOB_CANCELLED,
            "RETRY_PENDING": JobEventType.JOB_RETRY_SCHEDULED,
            "RESULT_REJECTED": JobEventType.JOB_RESULT_REJECTED,
        }

        event_type = event_type_map.get(
            transition.new_state,
            JobEventType.JOB_PROGRESS_UPDATED,
        )

        event = JobEvent.create(
            event_type=event_type.value,
            job_id=transition.job_id,
            tenant_id=record.contract.tenant_id,
            mission_id=record.contract.mission_id,
            previous_state=transition.previous_state,
            new_state=transition.new_state,
            actor=actor or transition.actor,
            correlation_id=transition.correlation_id,
            causation_id=transition.causation_id,
            provenance=f"lifecycle_manager:{transition.actor}",
        )

        return self.emit(event)
