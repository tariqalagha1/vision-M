"""
HERMES-PARALLEL-DISCOVERY-001 — Discovery Types
================================================
All data models for the governed parallel discovery lifecycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class DiscoveryType(str, Enum):
    API_DISCOVERY = "API_DISCOVERY"
    DATA_SOURCE = "DATA_SOURCE"
    STRUCTURED_CATALOG = "STRUCTURED_CATALOG"
    ENDPOINT = "ENDPOINT"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_WEAKNESS = "AUTHORIZATION_WEAKNESS"
    INFORMATION_EXPOSURE = "INFORMATION_EXPOSURE"
    CONFIGURATION = "CONFIGURATION"
    PATTERN = "PATTERN"
    OTHER = "OTHER"


class PerspectiveStatus(str, Enum):
    CREATED = "CREATED"
    UNDER_ANALYSIS = "UNDER_ANALYSIS"
    SUBMITTED_TO_MANAGER = "SUBMITTED_TO_MANAGER"
    REWORK_REQUIRED = "REWORK_REQUIRED"
    MANAGER_APPROVED = "MANAGER_APPROVED"
    MANAGER_REJECTED = "MANAGER_REJECTED"
    TIMED_OUT = "TIMED_OUT"
    ESCALATED = "ESCALATED"


class DecisionType(str, Enum):
    CONSUME_IN_CURRENT_MISSION = "CONSUME_IN_CURRENT_MISSION"
    APPROVE_NEW_INTERNAL_PHASE = "APPROVE_NEW_INTERNAL_PHASE"
    REQUEST_ADDITIONAL_AUTHORIZATION = "REQUEST_ADDITIONAL_AUTHORIZATION"
    DEFER_WITH_REASON = "DEFER_WITH_REASON"
    REJECT_AS_LOW_VALUE = "REJECT_AS_LOW_VALUE"
    REJECT_AS_INVALID = "REJECT_AS_INVALID"
    BLOCK_BY_AUTHORIZATION = "BLOCK_BY_AUTHORIZATION"
    CLOSE_AFTER_REVIEW = "CLOSE_AFTER_REVIEW"


# ═══════════════════════════════════════════════════════════════
# Core data classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class DiscoveryPerspective:
    perspective_id: str
    discovery_id: str
    mission_id: str
    correlation_id: str

    gear: str
    producing_agent_id: str
    approving_manager_id: str

    interpretation: str
    evidence_ids: list[str]
    opportunities: list[str]
    risks: list[str]
    uncertainties: list[str]
    contradictions: list[str]
    recommended_actions: list[str]

    operational_impact: str
    data_acquisition_impact: str
    mining_impact: str
    security_impact: str
    scope_impact: str
    authorization_impact: str

    confidence: float
    status: str

    created_at: str
    manager_reviewed_at: Optional[str] = None

    # Version tracking for perspective updates
    version: int = 1
    previous_version_id: Optional[str] = None

    @classmethod
    def create(cls, **kwargs) -> DiscoveryPerspective:
        if "perspective_id" not in kwargs:
            kwargs["perspective_id"] = str(uuid.uuid4())
        if "created_at" not in kwargs:
            kwargs["created_at"] = datetime.now(timezone.utc).isoformat()
        if "status" not in kwargs:
            kwargs["status"] = PerspectiveStatus.CREATED.value
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "perspective_id": self.perspective_id,
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
            "gear": self.gear,
            "producing_agent_id": self.producing_agent_id,
            "approving_manager_id": self.approving_manager_id,
            "interpretation": self.interpretation,
            "evidence_ids": self.evidence_ids,
            "opportunities": self.opportunities,
            "risks": self.risks,
            "uncertainties": self.uncertainties,
            "contradictions": self.contradictions,
            "recommended_actions": self.recommended_actions,
            "operational_impact": self.operational_impact,
            "data_acquisition_impact": self.data_acquisition_impact,
            "mining_impact": self.mining_impact,
            "security_impact": self.security_impact,
            "scope_impact": self.scope_impact,
            "authorization_impact": self.authorization_impact,
            "confidence": self.confidence,
            "status": self.status,
            "created_at": self.created_at,
            "manager_reviewed_at": self.manager_reviewed_at,
            "version": self.version,
            "previous_version_id": self.previous_version_id,
        }


@dataclass
class DiscoveryRecord:
    discovery_id: str
    mission_id: str
    correlation_id: str
    causation_id: str
    source_gear: str
    source_agent_id: str
    source_manager_id: str
    discovery_types: list[str]
    materiality: str
    evidence_references: list[str]
    title: str
    description: str
    status: str  # REGISTERED, BROADCAST, IN_REVIEW, SYNTHESIZED, DECIDED, CLOSED
    created_at: str
    updated_at: str
    broadcast_at: Optional[str] = None

    @classmethod
    def create(cls, **kwargs) -> DiscoveryRecord:
        if "discovery_id" not in kwargs:
            kwargs["discovery_id"] = str(uuid.uuid4())
        if "correlation_id" not in kwargs:
            kwargs["correlation_id"] = str(uuid.uuid4())
        if "causation_id" not in kwargs:
            kwargs["causation_id"] = str(uuid.uuid4())
        if "created_at" not in kwargs:
            kwargs["created_at"] = datetime.now(timezone.utc).isoformat()
        if "updated_at" not in kwargs:
            kwargs["updated_at"] = datetime.now(timezone.utc).isoformat()
        if "status" not in kwargs:
            kwargs["status"] = "REGISTERED"
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "source_gear": self.source_gear,
            "source_agent_id": self.source_agent_id,
            "source_manager_id": self.source_manager_id,
            "discovery_types": self.discovery_types,
            "materiality": self.materiality,
            "evidence_references": self.evidence_references,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "broadcast_at": self.broadcast_at,
        }


@dataclass
class GateResult:
    gate_name: str
    passed: bool
    missing: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "gate_name": self.gate_name,
            "passed": self.passed,
            "missing": self.missing,
            "failures": self.failures,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class SynthesisResult:
    synthesis_id: str
    discovery_id: str
    mission_id: str
    scraping_established: str
    mining_established: str
    security_established: str
    evidence_established: str
    areas_of_agreement: list[str]
    areas_of_contradiction: list[str]
    unresolved_uncertainty: list[str]
    scope_implications: str
    authorization_implications: str
    safe_options: list[str]
    blocked_options: list[str]
    recommended_next_phase_options: list[str]
    created_at: str
    produced_by: str  # Evidence Integration Manager

    @classmethod
    def create(cls, **kwargs) -> SynthesisResult:
        if "synthesis_id" not in kwargs:
            kwargs["synthesis_id"] = str(uuid.uuid4())
        if "created_at" not in kwargs:
            kwargs["created_at"] = datetime.now(timezone.utc).isoformat()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "synthesis_id": self.synthesis_id,
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "scraping_established": self.scraping_established,
            "mining_established": self.mining_established,
            "security_established": self.security_established,
            "evidence_established": self.evidence_established,
            "areas_of_agreement": self.areas_of_agreement,
            "areas_of_contradiction": self.areas_of_contradiction,
            "unresolved_uncertainty": self.unresolved_uncertainty,
            "scope_implications": self.scope_implications,
            "authorization_implications": self.authorization_implications,
            "safe_options": self.safe_options,
            "blocked_options": self.blocked_options,
            "recommended_next_phase_options": self.recommended_next_phase_options,
            "created_at": self.created_at,
            "produced_by": self.produced_by,
        }


@dataclass
class ManagementDecision:
    decision_id: str
    discovery_id: str
    mission_id: str
    program_manager_assessment: str
    mission_value: str
    operational_priority: str
    dependencies: list[str]
    workload_impact: str
    resource_implications: str
    proposed_ownership: str
    phase_justification: str
    mission_director_choice: str  # DecisionType
    independent_reviewer_notes: str
    created_at: str
    decided_by: str

    @classmethod
    def create(cls, **kwargs) -> ManagementDecision:
        if "decision_id" not in kwargs:
            kwargs["decision_id"] = str(uuid.uuid4())
        if "created_at" not in kwargs:
            kwargs["created_at"] = datetime.now(timezone.utc).isoformat()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "program_manager_assessment": self.program_manager_assessment,
            "mission_value": self.mission_value,
            "operational_priority": self.operational_priority,
            "dependencies": self.dependencies,
            "workload_impact": self.workload_impact,
            "resource_implications": self.resource_implications,
            "proposed_ownership": self.proposed_ownership,
            "phase_justification": self.phase_justification,
            "mission_director_choice": self.mission_director_choice,
            "independent_reviewer_notes": self.independent_reviewer_notes,
            "created_at": self.created_at,
            "decided_by": self.decided_by,
        }


@dataclass
class AcknowledgmentRecord:
    discovery_id: str
    gear: str
    agent_id: str
    received_at: str
    acknowledged_at: Optional[str] = None
    status: str = "PENDING"  # PENDING, ACKNOWLEDGED, TIMED_OUT

    def to_dict(self) -> dict:
        return {
            "discovery_id": self.discovery_id,
            "gear": self.gear,
            "agent_id": self.agent_id,
            "received_at": self.received_at,
            "acknowledged_at": self.acknowledged_at,
            "status": self.status,
        }
