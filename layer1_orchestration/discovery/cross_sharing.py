"""
HERMES-PARALLEL-DISCOVERY-001 — Cross-Gear Perspective Sharing
Each manager-approved perspective is republished to all other gears.
Other gears may add observations, challenge assumptions, request
clarification, update their perspective, or open a contradiction.
All versions are preserved — no silent overwrites.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .discovery_types import DiscoveryPerspective, PerspectiveStatus
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class CrossSharingEngine:
    """Cross-gear perspective sharing engine.

    When a perspective is manager-approved:
    1. It is published to all other gears via gear-specific events
    2. Other gears receive it and may respond
    3. Responses are tracked as observations, challenges, clarifications,
       updates, or contradictions

    Events emitted:
    - SCRAPING_PERSPECTIVE_PUBLISHED
    - MINING_PERSPECTIVE_PUBLISHED
    - SECURITY_PERSPECTIVE_PUBLISHED
    - EVIDENCE_PERSPECTIVE_PUBLISHED
    """

    GEAR_PUBLISHED_EVENTS = {
        "scraping": DiscoveryEventType.SCRAPING_PERSPECTIVE_PUBLISHED,
        "mining": DiscoveryEventType.MINING_PERSPECTIVE_PUBLISHED,
        "security": DiscoveryEventType.SECURITY_PERSPECTIVE_PUBLISHED,
        "evidence": DiscoveryEventType.EVIDENCE_PERSPECTIVE_PUBLISHED,
    }

    ALL_GEARS = {"scraping", "mining", "security", "evidence"}

    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._exchanges: List[dict] = []  # All cross-gear exchanges
        self._observations: Dict[str, List[dict]] = {}  # perspective_id -> [observations]
        self._challenges: Dict[str, List[dict]] = {}    # perspective_id -> [challenges]
        self._clarification_requests: Dict[str, List[dict]] = {}  # perspective_id -> [requests]

    def publish_approved_perspective(
        self,
        perspective: DiscoveryPerspective,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
    ) -> None:
        """Publish a manager-approved perspective to all OTHER gears.

        The perspective's own gear does not receive its own publication.
        Emits: <GEAR>_PERSPECTIVE_PUBLISHED for all other gears.
        """
        if perspective.status != PerspectiveStatus.MANAGER_APPROVED.value:
            raise ValueError(
                f"Cannot publish unapproved perspective: {perspective.status}. "
                f"Must be MANAGER_APPROVED."
            )

        # Publish to all OTHER gears
        for target_gear in self.ALL_GEARS - {perspective.gear}:
            event_type = self.GEAR_PUBLISHED_EVENTS.get(perspective.gear)
            if event_type:
                self._event_bus.publish(DiscoveryEvent.create(
                    event_type=event_type,
                    discovery_id=perspective.discovery_id,
                    mission_id=mission_id,
                    correlation_id=correlation_id,
                    causation_id=causation_id,
                    producer=perspective.gear,
                    receiver=target_gear,
                    gear=perspective.gear,
                    manager=perspective.approving_manager_id,
                    evidence_reference=perspective.perspective_id,
                    data={
                        "perspective_id": perspective.perspective_id,
                        "source_gear": perspective.gear,
                        "target_gear": target_gear,
                        "interpretation_summary": perspective.interpretation[:200],
                        "confidence": perspective.confidence,
                    },
                ))

        # Also emit general PERSPECTIVE_PUBLISHED
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.PERSPECTIVE_PUBLISHED,
            discovery_id=perspective.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=perspective.gear,
            receiver="ALL",
            gear=perspective.gear,
            manager=perspective.approving_manager_id,
            evidence_reference=perspective.perspective_id,
        ))

        self._log_exchange("PUBLISHED", perspective.gear, "ALL", perspective.perspective_id)

    def add_observation(
        self,
        perspective_id: str,
        observing_gear: str,
        observation: str,
        agent_id: str,
    ) -> dict:
        """Another gear adds an observation on a published perspective."""
        entry = {
            "id": str(uuid.uuid4()),
            "perspective_id": perspective_id,
            "observing_gear": observing_gear,
            "agent_id": agent_id,
            "observation": observation,
            "type": "OBSERVATION",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if perspective_id not in self._observations:
            self._observations[perspective_id] = []
        self._observations[perspective_id].append(entry)
        self._log_exchange("OBSERVATION", observing_gear, perspective_id, f"observation: {observation[:80]}")
        return entry

    def add_challenge(
        self,
        perspective_id: str,
        challenging_gear: str,
        challenge: str,
        agent_id: str,
    ) -> dict:
        """Another gear challenges an assumption in a published perspective."""
        entry = {
            "id": str(uuid.uuid4()),
            "perspective_id": perspective_id,
            "challenging_gear": challenging_gear,
            "agent_id": agent_id,
            "challenge": challenge,
            "type": "CHALLENGE",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if perspective_id not in self._challenges:
            self._challenges[perspective_id] = []
        self._challenges[perspective_id].append(entry)
        self._log_exchange("CHALLENGE", challenging_gear, perspective_id, f"challenge: {challenge[:80]}")
        return entry

    def request_clarification(
        self,
        perspective_id: str,
        requesting_gear: str,
        clarification: str,
        agent_id: str,
    ) -> dict:
        """Another gear requests clarification on a perspective."""
        entry = {
            "id": str(uuid.uuid4()),
            "perspective_id": perspective_id,
            "requesting_gear": requesting_gear,
            "agent_id": agent_id,
            "clarification": clarification,
            "type": "CLARIFICATION_REQUEST",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if perspective_id not in self._clarification_requests:
            self._clarification_requests[perspective_id] = []
        self._clarification_requests[perspective_id].append(entry)
        self._log_exchange("CLARIFICATION_REQUEST", requesting_gear, perspective_id, clarification[:80])
        return entry

    def update_perspective(
        self,
        original: DiscoveryPerspective,
        updated_interpretation: str,
        agent_id: str,
    ) -> DiscoveryPerspective:
        """Create a new version of a perspective (preserves original).

        The original remains in version history. The new version
        gets version = original.version + 1 and references the previous.
        """
        new_perspective = DiscoveryPerspective.create(
            discovery_id=original.discovery_id,
            mission_id=original.mission_id,
            correlation_id=original.correlation_id,
            gear=original.gear,
            producing_agent_id=agent_id,
            approving_manager_id=original.approving_manager_id,
            interpretation=updated_interpretation,
            evidence_ids=list(original.evidence_ids),
            opportunities=list(original.opportunities),
            risks=list(original.risks),
            uncertainties=list(original.uncertainties),
            contradictions=list(original.contradictions),
            recommended_actions=list(original.recommended_actions),
            operational_impact=original.operational_impact,
            data_acquisition_impact=original.data_acquisition_impact,
            mining_impact=original.mining_impact,
            security_impact=original.security_impact,
            scope_impact=original.scope_impact,
            authorization_impact=original.authorization_impact,
            confidence=original.confidence,
            status=PerspectiveStatus.CREATED.value,
        )
        new_perspective.version = original.version + 1
        new_perspective.previous_version_id = original.perspective_id

        self._log_exchange("UPDATED", original.gear, original.perspective_id,
                          f"version {original.version} → {new_perspective.version}")
        return new_perspective

    def open_contradiction(
        self,
        perspective_id: str,
        contradicting_gear: str,
        contradiction: str,
        agent_id: str,
    ) -> dict:
        """Open a formal contradiction against a perspective."""
        entry = {
            "id": str(uuid.uuid4()),
            "perspective_id": perspective_id,
            "contradicting_gear": contradicting_gear,
            "agent_id": agent_id,
            "contradiction": contradiction,
            "type": "CONTRADICTION",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Also add to challenges for tracking
        if perspective_id not in self._challenges:
            self._challenges[perspective_id] = []
        self._challenges[perspective_id].append(entry)
        self._log_exchange("CONTRADICTION", contradicting_gear, perspective_id, contradiction[:80])
        return entry

    def get_observations(self, perspective_id: str) -> List[dict]:
        return self._observations.get(perspective_id, [])

    def get_challenges(self, perspective_id: str) -> List[dict]:
        return self._challenges.get(perspective_id, [])

    def get_exchanges(self) -> List[dict]:
        return list(self._exchanges)

    def has_contradictions(self, perspective_id: str) -> bool:
        """Check if any contradictions exist for a perspective."""
        challenges = self._challenges.get(perspective_id, [])
        return any(c.get("type") == "CONTRADICTION" for c in challenges)

    def _log_exchange(self, action: str, source: str, target: str, detail: str) -> None:
        self._exchanges.append({
            "action": action,
            "source": source,
            "target": target,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
