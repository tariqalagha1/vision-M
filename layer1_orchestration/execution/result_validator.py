"""
ATLAS — Result Validation Gate
===============================
Independent validation of completed job results before they become findings.
Only ACCEPTED results may advance the finding chain.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .job_contract import (
    JobRecord, JobState, ValidationDecision,
)
from .job_lifecycle import JobLifecycleManager
from .job_store import JobStore


class ResultValidator:
    """Independent validation gate for completed job results.

    A COMPLETED worker result is NOT automatically accepted.
    The validator confirms the output meets the job contract before
    allowing it to become a finding.
    """

    def __init__(self, store: JobStore, lifecycle: JobLifecycleManager):
        self.store = store
        self.lifecycle = lifecycle

    # ── Public API ──────────────────────────────────────────────

    def validate(
        self,
        record: JobRecord,
        validator_id: str,
    ) -> Dict[str, Any]:
        """Validate a completed job result.

        Returns a dict with 'decision' (ValidationDecision) and 'reason'.
        Only ACCEPTED enables chain advancement.
        """
        # Guard: only validate COMPLETED jobs
        if record.current_state != JobState.COMPLETED.value:
            return {
                "decision": ValidationDecision.REJECTED,
                "reason": f"Job is not COMPLETED (current: {record.current_state})",
            }

        # Guard: must have a completion result
        if not record.completion_result:
            return {
                "decision": ValidationDecision.INCOMPLETE,
                "reason": "No completion result present",
            }

        # Run all validation checks
        failures = []

        # 1. Output matches contract
        failures.extend(self._check_contract_match(record))

        # 2. Execution remained within authorization
        failures.extend(self._check_authorization(record))

        # 3. Required evidence is present
        failures.extend(self._check_evidence(record))

        # 4. Provenance is complete
        failures.extend(self._check_provenance(record))

        # 5. Completion criteria were met
        failures.extend(self._check_completion_criteria(record))

        # 6. No stop condition was violated
        failures.extend(self._check_stop_conditions(record))

        # 7. No duplicate result
        failures.extend(self._check_duplicate(record))

        # 8. Tenant and job match
        failures.extend(self._check_tenant_job_match(record))

        # 9. Confidence and limitations documented
        failures.extend(self._check_confidence(record))

        # 10. Contradictions preserved
        failures.extend(self._check_contradictions(record))

        # Decide
        if not failures:
            decision = ValidationDecision.ACCEPTED
            reason = "All validation checks passed."
        else:
            # Classify the worst failure
            worst = self._classify_failure(failures)
            decision = worst
            reason = "; ".join(failures)

        # Apply the decision
        record.validation_decision = decision.value
        record.validation_reason = reason
        record.validated_at = datetime.now(timezone.utc).isoformat()
        record.validated_by = validator_id

        if decision == ValidationDecision.ACCEPTED:
            # Accepted — stays in COMPLETED, eligible for chain advancement
            pass
        elif decision == ValidationDecision.REJECTED:
            self.lifecycle.transition(record, JobState.RESULT_REJECTED,
                actor=validator_id, reason=reason)
        # Other decisions leave the job in COMPLETED but mark it

        self.store.save(record)

        return {
            "decision": decision.value,
            "reason": reason,
            "failures": failures,
            "job_id": record.contract.job_id,
        }

    # ── Validation checks ───────────────────────────────────────

    def _check_contract_match(self, record: JobRecord) -> List[str]:
        failures = []
        result = record.completion_result or {}
        expected = record.contract.expected_output_contract
        if expected:
            for key in expected:
                if key not in result:
                    failures.append(f"Contract mismatch: missing '{key}' in result")
        return failures

    def _check_authorization(self, record: JobRecord) -> List[str]:
        failures = []
        if not record.contract.authorization_reference:
            failures.append("Missing authorization reference")
        # Check authorization wasn't revoked during execution
        for event in record.stop_events:
            if event.get("type") == "AUTHORIZATION_REVOKED":
                failures.append("Authorization was revoked during execution")
        return failures

    def _check_evidence(self, record: JobRecord) -> List[str]:
        failures = []
        result = record.completion_result or {}
        evidence = result.get("evidence_references", [])
        if not evidence and not record.evidence_references:
            failures.append("No evidence references in result")
        return failures

    def _check_provenance(self, record: JobRecord) -> List[str]:
        failures = []
        if not record.execution_started_at:
            failures.append("Missing execution start timestamp")
        if not record.execution_completed_at:
            failures.append("Missing execution completion timestamp")
        if not record.state_history:
            failures.append("Empty state history — provenance lost")
        return failures

    def _check_completion_criteria(self, record: JobRecord) -> List[str]:
        failures = []
        result = record.completion_result or {}
        if not result.get("summary"):
            failures.append("No completion summary in result")
        return failures

    def _check_stop_conditions(self, record: JobRecord) -> List[str]:
        failures = []
        for event in record.stop_events:
            if "violated" in event.get("type", "").lower():
                failures.append(f"Stop condition triggered: {event}")
        return failures

    def _check_duplicate(self, record: JobRecord) -> List[str]:
        failures = []
        # Check if this job ID has already been validated
        existing = self.store.load(record.contract.job_id)
        if existing and existing.validation_decision == ValidationDecision.ACCEPTED.value:
            failures.append("Duplicate: this job has already been accepted")
        return failures

    def _check_tenant_job_match(self, record: JobRecord) -> List[str]:
        failures = []
        result = record.completion_result or {}
        result_tenant = result.get("tenant_id", "")
        if result_tenant and result_tenant != record.contract.tenant_id:
            failures.append(
                f"Tenant mismatch: result tenant '{result_tenant}' != job tenant '{record.contract.tenant_id}'"
            )
        return failures

    def _check_confidence(self, record: JobRecord) -> List[str]:
        failures = []
        result = record.completion_result or {}
        # Must document confidence or explicitly state it's unknown
        if "confidence" not in result and "limitations" not in result:
            failures.append("Result missing confidence or limitations documentation")
        return failures

    def _check_contradictions(self, record: JobRecord) -> List[str]:
        # Contradictions should be preserved, not failure
        return []

    def _classify_failure(self, failures: List[str]) -> ValidationDecision:
        """Classify the worst validation failure."""
        combined = " ".join(failures).lower()
        if "scope" in combined:
            return ValidationDecision.SCOPE_VIOLATION
        if "contract mismatch" in combined:
            return ValidationDecision.CONTRACT_MISMATCH
        if "evidence" in combined or "no evidence" in combined:
            return ValidationDecision.EVIDENCE_INSUFFICIENT
        if "incomplete" in combined:
            return ValidationDecision.INCOMPLETE
        if "duplicate" in combined:
            return ValidationDecision.REJECTED
        return ValidationDecision.REQUIRES_REVIEW
