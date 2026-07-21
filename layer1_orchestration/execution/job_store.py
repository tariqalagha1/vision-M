"""
ATLAS — Job Store
=================
Durable JSON persistence for job records. Survives process restarts.
A job that exists only in memory does not qualify.
"""
from __future__ import annotations

import json
import os
import fcntl
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .job_contract import JobRecord


class JobStore:
    """Durable persistent store for job records.

    Uses per-job JSON files with file locking for safe concurrent access.
    Jobs survive process termination, restarts, and worker crashes.
    """

    def __init__(self, storage_dir: str = ""):
        if not storage_dir:
            storage_dir = os.environ.get(
                "ATLAS_JOB_STORE_PATH",
                "/tmp/atlas_jobs"
            )
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

    # ── CRUD ────────────────────────────────────────────────────

    def save(self, record: JobRecord) -> str:
        """Persist a job record. Returns the file path."""
        record.updated_at = datetime.now(timezone.utc).isoformat()
        filepath = self._path_for(record.contract.job_id)

        data = record.to_dict()
        tmp_path = filepath + ".tmp"

        with open(tmp_path, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                json.dump(data, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        os.rename(tmp_path, filepath)
        return filepath

    def load(self, job_id: str) -> Optional[JobRecord]:
        """Load a job record by ID. Returns None if not found."""
        filepath = self._path_for(job_id)
        if not os.path.exists(filepath):
            return None

        with open(filepath, "r") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

        return JobRecord.from_dict(data)

    def delete(self, job_id: str) -> bool:
        """Delete a job record. Returns True if it existed."""
        filepath = self._path_for(job_id)
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False

    def exists(self, job_id: str) -> bool:
        """Check if a job record exists."""
        return os.path.exists(self._path_for(job_id))

    def list_jobs(self, tenant_id: Optional[str] = None) -> List[str]:
        """List all persisted job IDs, optionally filtered by tenant."""
        jobs = []
        for fname in os.listdir(self.storage_dir):
            if fname.endswith(".json"):
                job_id = fname[:-5]  # Strip .json
                if tenant_id:
                    record = self.load(job_id)
                    if record and record.contract.tenant_id == tenant_id:
                        jobs.append(job_id)
                else:
                    jobs.append(job_id)
        return sorted(jobs)

    def find_by_idempotency_key(self, key: str) -> Optional[JobRecord]:
        """Find a job by its idempotency key (prevents duplicate submission)."""
        if not key:
            return None
        for job_id in self.list_jobs():
            record = self.load(job_id)
            if record and record.contract.idempotency_key == key:
                return record
        return None

    # ── Helpers ─────────────────────────────────────────────────

    def _path_for(self, job_id: str) -> str:
        return os.path.join(self.storage_dir, f"{job_id}.json")
