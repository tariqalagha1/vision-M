"""
HERMES-PARALLEL-DISCOVERY-001 — Manager Review Workflow
Every gear perspective must be reviewed by its responsible manager.
Path: Specialist creates → Manager reviews → PASS or REWORK_REQUIRED
→ Corrected → MANAGER_APPROVED
Unapproved specialist perspectives must not satisfy the decision gate.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .discovery_types import DiscoveryPerspective, PerspectiveStatus
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class ManagerReviewWorkflow:
    """Manager review workflow for gear perspectives.

    Required path:
    1. Specialist creates perspective (CREATED → UNDER_ANALYSIS)
    2. Specialist submits to manager (SUBMITTED_TO_MANAGER)
    3. Manager reviews (PASS → MANAGER_APPROVED or REWORK_REQUIRED)
    4. If rework: specialist corrects → resubmits
    5. Manager approves → MANAGER_APPROVED

    Also handles: MANAGER_REJECTED, TIMED_OUT, ESCALATED
    """

    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._review_log: List[dict] = []

    def submit_to_manager(
        self,
        perspective: DiscoveryPerspective,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
    ) -> DiscoveryPerspective:
        """Submit a perspective for manager review.

        Transitions: UNDER_ANALYSIS → SUBMITTED_TO_MANAGER
        """
        perspective.status = PerspectiveStatus.SUBMITTED_TO_MANAGER.value

        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.PERSPECTIVE_SUBMITTED_TO_MANAGER,
            discovery_id=perspective.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=perspective.producing_agent_id,
            receiver=perspective.approving_manager_id or "MANAGER",
            gear=perspective.gear,
            manager=perspective.approving_manager_id or "MANAGER",
            evidence_reference=perspective.perspective_id,
            data={"perspective_id": perspective.perspective_id, "gear": perspective.gear},
        ))

        self._log_review(perspective.perspective_id, "SUBMITTED_TO_MANAGER", perspective.gear)
        return perspective

    def review(
        self,
        perspective: DiscoveryPerspective,
        manager_id: str,
        decision: str,  # "PASS" or "REWORK_REQUIRED"
        notes: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
    ) -> DiscoveryPerspective:
        """Manager reviews a perspective.

        PASS → MANAGER_APPROVED
        REWORK_REQUIRED → REWORK_REQUIRED
        """
        if decision == "PASS":
            perspective.status = PerspectiveStatus.MANAGER_APPROVED.value
            perspective.approving_manager_id = manager_id
            perspective.manager_reviewed_at = datetime.now(timezone.utc).isoformat()

            self._event_bus.publish(DiscoveryEvent.create(
                event_type=DiscoveryEventType.PERSPECTIVE_MANAGER_APPROVED,
                discovery_id=perspective.discovery_id,
                mission_id=mission_id,
                correlation_id=correlation_id,
                causation_id=causation_id,
                producer=manager_id,
                receiver=perspective.producing_agent_id,
                gear=perspective.gear,
                manager=manager_id,
                evidence_reference=perspective.perspective_id,
                data={"perspective_id": perspective.perspective_id, "notes": notes},
            ))
        else:
            perspective.status = PerspectiveStatus.REWORK_REQUIRED.value

            self._event_bus.publish(DiscoveryEvent.create(
                event_type=DiscoveryEventType.PERSPECTIVE_REWORK_REQUIRED,
                discovery_id=perspective.discovery_id,
                mission_id=mission_id,
                correlation_id=correlation_id,
                causation_id=causation_id,
                producer=manager_id,
                receiver=perspective.producing_agent_id,
                gear=perspective.gear,
                manager=manager_id,
                evidence_reference=perspective.perspective_id,
                data={"perspective_id": perspective.perspective_id, "notes": notes, "rework_reason": notes},
            ))

        self._log_review(perspective.perspective_id, decision, perspective.gear, manager_id, notes)
        return perspective

    def reject(
        self,
        perspective: DiscoveryPerspective,
        manager_id: str,
        reason: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
    ) -> DiscoveryPerspective:
        """Manager rejects a perspective outright."""
        perspective.status = PerspectiveStatus.MANAGER_REJECTED.value

        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_PERSPECTIVE_GATE_FAILED,
            discovery_id=perspective.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=manager_id,
            receiver=perspective.producing_agent_id,
            gear=perspective.gear,
            manager=manager_id,
            evidence_reference=perspective.perspective_id,
            data={"reason": reason},
        ))

        self._log_review(perspective.perspective_id, "MANAGER_REJECTED", perspective.gear, manager_id, reason)
        return perspective

    def escalate(
        self,
        perspective: DiscoveryPerspective,
        agent_id: str,
        reason: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
    ) -> DiscoveryPerspective:
        """Escalate a perspective (timeout or unresolved)."""
        perspective.status = PerspectiveStatus.ESCALATED.value

        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.PERSPECTIVE_PUBLISHED,
            discovery_id=perspective.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=agent_id,
            receiver="PROGRAM_MANAGER",
            gear=perspective.gear,
            manager="",
            evidence_reference=perspective.perspective_id,
            data={"reason": reason, "status": "ESCALATED"},
        ))

        self._log_review(perspective.perspective_id, "ESCALATED", perspective.gear, agent_id, reason)
        return perspective

    def mark_timed_out(
        self,
        perspective: DiscoveryPerspective,
    ) -> DiscoveryPerspective:
        """Mark a perspective as timed out."""
        perspective.status = PerspectiveStatus.TIMED_OUT.value
        self._log_review(perspective.perspective_id, "TIMED_OUT", perspective.gear)
        return perspective

    def get_review_log(self) -> List[dict]:
        return list(self._review_log)

    def _log_review(
        self,
        perspective_id: str,
        action: str,
        gear: str,
        manager_id: str = "",
        notes: str = "",
    ) -> None:
        self._review_log.append({
            "perspective_id": perspective_id,
            "action": action,
            "gear": gear,
            "manager_id": manager_id,
            "notes": notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
