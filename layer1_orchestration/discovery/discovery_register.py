"""
HERMES-PARALLEL-DISCOVERY-001 — Discovery Register
====================================================
Central lifecycle registry. Every material discovery is tracked here.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .discovery_types import (
    DiscoveryRecord, DiscoveryPerspective, SynthesisResult,
    ManagementDecision, AcknowledgmentRecord,
)


class DiscoveryRegister:
    """Central registry for all discovery lifecycles.

    Tracks: registration, broadcast, perspectives, acknowledgments,
    synthesis, and management decisions.
    """

    REQUIRED_GEARS = {"scraping", "mining", "security", "evidence"}

    def __init__(self, storage_dir: str = "."):
        self.storage_dir = storage_dir
        self._discoveries: Dict[str, DiscoveryRecord] = {}
        self._perspectives: Dict[str, Dict[str, List[DiscoveryPerspective]]] = {}  # discovery_id -> {gear -> [versions]}
        self._acknowledgments: Dict[str, Dict[str, AcknowledgmentRecord]] = {}  # discovery_id -> {gear -> ack}
        self._syntheses: Dict[str, SynthesisResult] = {}
        self._decisions: Dict[str, ManagementDecision] = {}
        self._contradictions: Dict[str, List[dict]] = {}
        self._cross_gear_exchanges: List[dict] = []
        self._manager_reviews: List[dict] = []

    def register_discovery(self, **kwargs) -> DiscoveryRecord:
        """Register a new material discovery.
        Returns the DiscoveryRecord.
        """
        record = DiscoveryRecord.create(**kwargs)
        self._discoveries[record.discovery_id] = record
        self._perspectives[record.discovery_id] = {}
        self._acknowledgments[record.discovery_id] = {}
        self._contradictions[record.discovery_id] = []
        return record

    def get_discovery(self, discovery_id: str) -> Optional[DiscoveryRecord]:
        return self._discoveries.get(discovery_id)

    def update_discovery_status(self, discovery_id: str, status: str) -> None:
        """Update the lifecycle status of a discovery."""
        if discovery_id in self._discoveries:
            self._discoveries[discovery_id].status = status
            self._discoveries[discovery_id].updated_at = datetime.now(timezone.utc).isoformat()

    def record_acknowledgment(self, discovery_id: str, gear: str, agent_id: str) -> AcknowledgmentRecord:
        """Record that a gear acknowledged the discovery."""
        ack = AcknowledgmentRecord(
            discovery_id=discovery_id,
            gear=gear,
            agent_id=agent_id,
            received_at=datetime.now(timezone.utc).isoformat(),
            acknowledged_at=datetime.now(timezone.utc).isoformat(),
            status="ACKNOWLEDGED",
        )
        if discovery_id in self._acknowledgments:
            self._acknowledgments[discovery_id][gear] = ack
        return ack

    def has_all_acknowledgments(self, discovery_id: str) -> bool:
        """Check if all required gears have acknowledged."""
        if discovery_id not in self._acknowledgments:
            return False
        acks = self._acknowledgments[discovery_id]
        for gear in self.REQUIRED_GEARS:
            if gear not in acks or acks[gear].status != "ACKNOWLEDGED":
                return False
        return True

    def get_missing_acknowledgments(self, discovery_id: str) -> List[str]:
        """Get list of gears that haven't acknowledged."""
        if discovery_id not in self._acknowledgments:
            return sorted(self.REQUIRED_GEARS)
        acks = self._acknowledgments[discovery_id]
        return sorted([
            gear for gear in self.REQUIRED_GEARS
            if gear not in acks or acks[gear].status != "ACKNOWLEDGED"
        ])

    def add_perspective(self, discovery_id: str, perspective: DiscoveryPerspective) -> None:
        """Add a perspective. Multiple versions per gear are preserved."""
        if discovery_id not in self._perspectives:
            self._perspectives[discovery_id] = {}
        gear_perspectives = self._perspectives[discovery_id]
        if perspective.gear not in gear_perspectives:
            gear_perspectives[perspective.gear] = []
        gear_perspectives[perspective.gear].append(perspective)

    def get_perspectives(self, discovery_id: str) -> Dict[str, List[DiscoveryPerspective]]:
        """Get all perspectives for a discovery, grouped by gear."""
        return self._perspectives.get(discovery_id, {})

    def get_latest_perspectives(self, discovery_id: str) -> List[DiscoveryPerspective]:
        """Get the latest version of each gear's perspective."""
        result = []
        for gear, versions in self._perspectives.get(discovery_id, {}).items():
            if versions:
                result.append(versions[-1])
        return result

    def get_approved_perspectives(self, discovery_id: str) -> List[DiscoveryPerspective]:
        """Get only manager-approved perspectives."""
        return [
            p for p in self.get_latest_perspectives(discovery_id)
            if p.status == "MANAGER_APPROVED"
        ]

    def add_contradiction(self, discovery_id: str, contradiction: dict) -> None:
        """Register a contradiction."""
        if discovery_id not in self._contradictions:
            self._contradictions[discovery_id] = []
        self._contradictions[discovery_id].append(contradiction)

    def get_contradictions(self, discovery_id: str) -> List[dict]:
        return self._contradictions.get(discovery_id, [])

    def add_synthesis(self, synthesis: SynthesisResult) -> None:
        self._syntheses[synthesis.discovery_id] = synthesis

    def get_synthesis(self, discovery_id: str) -> Optional[SynthesisResult]:
        return self._syntheses.get(discovery_id)

    def add_decision(self, decision: ManagementDecision) -> None:
        self._decisions[decision.discovery_id] = decision

    def get_decision(self, discovery_id: str) -> Optional[ManagementDecision]:
        return self._decisions.get(discovery_id)

    def log_manager_review(self, review: dict) -> None:
        self._manager_reviews.append(review)

    def log_cross_gear_exchange(self, exchange: dict) -> None:
        self._cross_gear_exchanges.append(exchange)

    def query_by_status(self, status: str) -> List[DiscoveryRecord]:
        """Query all discoveries by lifecycle status."""
        return [d for d in self._discoveries.values() if d.status == status]

    def query_by_gear(self, gear: str) -> List[DiscoveryRecord]:
        """Query all discoveries by source gear."""
        return [d for d in self._discoveries.values() if d.source_gear == gear]

    def query_by_mission(self, mission_id: str) -> List[DiscoveryRecord]:
        """Query all discoveries for a mission."""
        return [d for d in self._discoveries.values() if d.mission_id == mission_id]

    def get_state(self, discovery_id: str) -> dict:
        """Get full state for a discovery."""
        discovery = self._discoveries.get(discovery_id)
        return {
            "discovery": discovery.to_dict() if discovery else None,
            "acknowledgments": {
                gear: ack.to_dict()
                for gear, ack in self._acknowledgments.get(discovery_id, {}).items()
            },
            "perspectives": {
                gear: [p.to_dict() for p in versions]
                for gear, versions in self._perspectives.get(discovery_id, {}).items()
            },
            "contradictions": self._contradictions.get(discovery_id, []),
            "synthesis": self._syntheses[discovery_id].to_dict() if discovery_id in self._syntheses else None,
            "decision": self._decisions[discovery_id].to_dict() if discovery_id in self._decisions else None,
        }

    def to_dict(self) -> dict:
        return {
            "discoveries": [d.to_dict() for d in self._discoveries.values()],
            "acknowledgment_count": sum(len(acks) for acks in self._acknowledgments.values()),
            "perspective_count": sum(
                len(versions) for gear_versions in self._perspectives.values()
                for versions in gear_versions.values()
            ),
            "synthesis_count": len(self._syntheses),
            "decision_count": len(self._decisions),
            "contradiction_count": sum(len(c) for c in self._contradictions.values()),
            "manager_review_count": len(self._manager_reviews),
            "cross_gear_exchange_count": len(self._cross_gear_exchanges),
        }
