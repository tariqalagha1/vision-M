"""
HERMES-FINDING-CHAIN-001 — Core Contracts
==========================================
All data models for the governed finding-chaining engine.
MYC-CHAIN-INV-001 enforced.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class FindingNodeType(str, Enum):
    OBSERVATION = "OBSERVATION"
    FINDING = "FINDING"
    HYPOTHESIS = "HYPOTHESIS"
    ACCESS_CONDITION = "ACCESS_CONDITION"
    DATA_SOURCE = "DATA_SOURCE"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    VALIDATION_TASK = "VALIDATION_TASK"
    IMPACT = "IMPACT"
    MITIGATION = "MITIGATION"
    AUTHORIZATION_BLOCKER = "AUTHORIZATION_BLOCKER"


class FindingEdgeType(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    MAY_ENABLE = "MAY_ENABLE"
    REQUIRES = "REQUIRES"
    VALIDATED_BY = "VALIDATED_BY"
    BLOCKED_BY = "BLOCKED_BY"
    AFFECTS = "AFFECTS"
    CROSSES_TRUST_BOUNDARY = "CROSSES_TRUST_BOUNDARY"
    REDUCES_CONFIDENCE = "REDUCES_CONFIDENCE"
    MITIGATED_BY = "MITIGATED_BY"


class HypothesisStatus(str, Enum):
    PROPOSED = "PROPOSED"
    UNDER_REVIEW = "UNDER_REVIEW"
    SAFE_VALIDATION_AVAILABLE = "SAFE_VALIDATION_AVAILABLE"
    REQUIRES_ADDITIONAL_AUTHORIZATION = "REQUIRES_ADDITIONAL_AUTHORIZATION"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    BLOCKED_BY_SCOPE = "BLOCKED_BY_SCOPE"
    BLOCKED_BY_AUTHORIZATION = "BLOCKED_BY_AUTHORIZATION"
    EXECUTED = "EXECUTED"
    VALIDATED = "VALIDATED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class AuthorizationStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    EXPIRED = "EXPIRED"


class ValidationStatus(str, Enum):
    UNVALIDATED = "UNVALIDATED"
    IN_PROGRESS = "IN_PROGRESS"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    PARTIAL = "PARTIAL"


class DispositionStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    DUPLICATE = "DUPLICATE"


# ═══════════════════════════════════════════════════════════════
# Event types
# ═══════════════════════════════════════════════════════════════

class ChainEventType(str, Enum):
    FINDING_REGISTERED = "FINDING_REGISTERED"
    FINDING_VALIDATED = "FINDING_VALIDATED"
    FINDING_BROADCAST = "FINDING_BROADCAST"
    CHAIN_HYPOTHESIS_CREATED = "CHAIN_HYPOTHESIS_CREATED"
    CHAIN_HYPOTHESIS_REVIEW_STARTED = "CHAIN_HYPOTHESIS_REVIEW_STARTED"
    CHAIN_HYPOTHESIS_APPROVED = "CHAIN_HYPOTHESIS_APPROVED"
    CHAIN_HYPOTHESIS_REJECTED = "CHAIN_HYPOTHESIS_REJECTED"
    CHAIN_BLOCKED_BY_SCOPE = "CHAIN_BLOCKED_BY_SCOPE"
    CHAIN_BLOCKED_BY_AUTHORIZATION = "CHAIN_BLOCKED_BY_AUTHORIZATION"
    TARGETED_RECON_REQUESTED = "TARGETED_RECON_REQUESTED"
    TARGETED_RECON_APPROVED = "TARGETED_RECON_APPROVED"
    CHAIN_VALIDATION_STARTED = "CHAIN_VALIDATION_STARTED"
    CHAIN_VALIDATION_STOPPED = "CHAIN_VALIDATION_STOPPED"
    CHAIN_VALIDATION_COMPLETED = "CHAIN_VALIDATION_COMPLETED"
    CHAIN_EDGE_VALIDATED = "CHAIN_EDGE_VALIDATED"
    CHAIN_EDGE_REJECTED = "CHAIN_EDGE_REJECTED"
    CHAIN_IMPACT_RECALCULATED = "CHAIN_IMPACT_RECALCULATED"
    CHAIN_CONTRADICTION_OPENED = "CHAIN_CONTRADICTION_OPENED"
    CHAIN_QA_REWORK_REQUIRED = "CHAIN_QA_REWORK_REQUIRED"
    CHAIN_QA_APPROVED = "CHAIN_QA_APPROVED"
    CHAIN_DISPOSITION_RECORDED = "CHAIN_DISPOSITION_RECORDED"
    # ── Phase 1 dispatch events ──
    CHAIN_DISPATCH_REQUESTED = "CHAIN_DISPATCH_REQUESTED"
    CHAIN_DISPATCH_AUTHORIZED = "CHAIN_DISPATCH_AUTHORIZED"
    CHAIN_DISPATCH_STARTED = "CHAIN_DISPATCH_STARTED"
    CHAIN_HYPOTHESIS_EXECUTED = "CHAIN_HYPOTHESIS_EXECUTED"
    CHAIN_DISPATCH_COMPLETED = "CHAIN_DISPATCH_COMPLETED"
    CHAIN_DISPATCH_FAILED = "CHAIN_DISPATCH_FAILED"
    CHAIN_EXECUTION_TERMINATED = "CHAIN_EXECUTION_TERMINATED"
    CHAIN_BUDGET_UPDATED = "CHAIN_BUDGET_UPDATED"
    CHAIN_LOOP_PREVENTED = "CHAIN_LOOP_PREVENTED"


# ═══════════════════════════════════════════════════════════════
# Core data classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class FindingNode:
    node_id: str
    mission_id: str
    correlation_id: str

    node_type: FindingNodeType
    title: str
    description: str

    source_gear: str
    source_agent_id: str
    approving_manager_id: Optional[str]

    evidence_ids: list[str] = field(default_factory=list)
    artifact_ids: list[str] = field(default_factory=list)

    observed_fact: str = ""
    inferred_meaning: Optional[str] = None

    confidence: float = 0.0
    severity: str = "info"
    materiality: str = "low"

    affected_assets: list[str] = field(default_factory=list)
    affected_trust_boundaries: list[str] = field(default_factory=list)

    authorization_status: str = "PENDING"
    validation_status: str = "UNVALIDATED"
    disposition_status: str = "OPEN"

    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ── Phase 1 chain fields ──
    chain_id: str = ""
    cascade_depth: int = 0
    hypothesis_id: str = ""
    budget_consumed: int = 0

    @classmethod
    def create(cls, **kwargs) -> FindingNode:
        if "node_id" not in kwargs:
            kwargs["node_id"] = str(uuid.uuid4())
        if "correlation_id" not in kwargs:
            kwargs["correlation_id"] = str(uuid.uuid4())
        if "approving_manager_id" not in kwargs:
            kwargs["approving_manager_id"] = None
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
            "node_type": self.node_type.value,
            "title": self.title,
            "description": self.description,
            "source_gear": self.source_gear,
            "source_agent_id": self.source_agent_id,
            "approving_manager_id": self.approving_manager_id,
            "evidence_ids": self.evidence_ids,
            "artifact_ids": self.artifact_ids,
            "observed_fact": self.observed_fact,
            "inferred_meaning": self.inferred_meaning,
            "confidence": self.confidence,
            "severity": self.severity,
            "materiality": self.materiality,
            "affected_assets": self.affected_assets,
            "affected_trust_boundaries": self.affected_trust_boundaries,
            "authorization_status": self.authorization_status,
            "validation_status": self.validation_status,
            "disposition_status": self.disposition_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class FindingEdge:
    edge_id: str
    mission_id: str
    correlation_id: str
    causation_id: str

    source_node_id: str
    target_node_id: str
    edge_type: FindingEdgeType

    source_role: str = ""
    source_gear: str = ""
    evidence_references: list[str] = field(default_factory=list)
    authorization_reference: str = ""
    scope_reference: str = ""
    confidence: float = 0.0

    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"

    @classmethod
    def create(cls, **kwargs) -> FindingEdge:
        if "edge_id" not in kwargs:
            kwargs["edge_id"] = str(uuid.uuid4())
        if "correlation_id" not in kwargs:
            kwargs["correlation_id"] = str(uuid.uuid4())
        if "causation_id" not in kwargs:
            kwargs["causation_id"] = str(uuid.uuid4())
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "edge_id": self.edge_id,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "source_role": self.source_role,
            "source_gear": self.source_gear,
            "evidence_references": self.evidence_references,
            "authorization_reference": self.authorization_reference,
            "scope_reference": self.scope_reference,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
        }


@dataclass
class ChainHypothesis:
    hypothesis_id: str
    mission_id: str
    parent_finding_ids: list[str]

    title: str
    rationale: str
    expected_observation: str
    target_asset: str
    proposed_method: str
    expected_evidence: list[str]

    risk_level: str = "low"
    scope_impact: str = "none"
    authorization_impact: str = "none"
    trust_boundary_impact: str = "none"

    safe_test_available: bool = False
    safe_test_description: Optional[str] = None

    proposed_by: str = ""
    reviewed_by: list[str] = field(default_factory=list)

    status: str = "PROPOSED"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_at: Optional[str] = None

    @classmethod
    def create(cls, **kwargs) -> ChainHypothesis:
        if "hypothesis_id" not in kwargs:
            kwargs["hypothesis_id"] = str(uuid.uuid4())
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id,
            "mission_id": self.mission_id,
            "parent_finding_ids": self.parent_finding_ids,
            "title": self.title,
            "rationale": self.rationale,
            "expected_observation": self.expected_observation,
            "target_asset": self.target_asset,
            "proposed_method": self.proposed_method,
            "expected_evidence": self.expected_evidence,
            "risk_level": self.risk_level,
            "scope_impact": self.scope_impact,
            "authorization_impact": self.authorization_impact,
            "trust_boundary_impact": self.trust_boundary_impact,
            "safe_test_available": self.safe_test_available,
            "safe_test_description": self.safe_test_description,
            "proposed_by": self.proposed_by,
            "reviewed_by": self.reviewed_by,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
        }


@dataclass
class FindingChainImpact:
    chain_id: str
    finding_ids: list[str]
    validated_edges: list[str]

    entry_condition: str = ""
    intermediate_conditions: list[str] = field(default_factory=list)
    final_demonstrated_impact: Optional[str] = None

    trust_boundaries_crossed: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    affected_data_classes: list[str] = field(default_factory=list)

    chain_confidence: float = 0.0
    chain_severity: str = "info"

    hypothetical_steps: list[str] = field(default_factory=list)
    validated_steps: list[str] = field(default_factory=list)
    blocked_steps: list[str] = field(default_factory=list)

    @classmethod
    def create(cls, **kwargs) -> FindingChainImpact:
        if "chain_id" not in kwargs:
            kwargs["chain_id"] = str(uuid.uuid4())
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "finding_ids": self.finding_ids,
            "validated_edges": self.validated_edges,
            "entry_condition": self.entry_condition,
            "intermediate_conditions": self.intermediate_conditions,
            "final_demonstrated_impact": self.final_demonstrated_impact,
            "trust_boundaries_crossed": self.trust_boundaries_crossed,
            "affected_assets": self.affected_assets,
            "affected_data_classes": self.affected_data_classes,
            "chain_confidence": self.chain_confidence,
            "chain_severity": self.chain_severity,
            "hypothetical_steps": self.hypothetical_steps,
            "validated_steps": self.validated_steps,
            "blocked_steps": self.blocked_steps,
        }


@dataclass
class TargetedReconRequest:
    request_id: str
    trigger_finding_ids: list[str]
    objective: str
    approved_assets: list[str]
    approved_methods: list[str]
    request_budget: int
    expected_evidence: list[str]
    manager_id: str
    authorization_reference: str

    @classmethod
    def create(cls, **kwargs) -> TargetedReconRequest:
        if "request_id" not in kwargs:
            kwargs["request_id"] = str(uuid.uuid4())
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "trigger_finding_ids": self.trigger_finding_ids,
            "objective": self.objective,
            "approved_assets": self.approved_assets,
            "approved_methods": self.approved_methods,
            "request_budget": self.request_budget,
            "expected_evidence": self.expected_evidence,
            "manager_id": self.manager_id,
            "authorization_reference": self.authorization_reference,
        }


@dataclass
class ChainEvent:
    event_id: str
    mission_id: str
    chain_id: str
    finding_id: str
    hypothesis_id: str
    correlation_id: str
    causation_id: str
    event_type: ChainEventType
    producer_role: str
    receiver_role: str
    evidence_reference: str
    authorization_reference: str
    timestamp: str
    status: str
    reason: str = ""
    # ── Phase 1 dispatch fields ──
    source_engine: str = ""
    target_engine: str = ""
    depth: int = 0
    asset: str = ""
    outcome: str = ""

    @classmethod
    def create(cls, **kwargs) -> ChainEvent:
        if "event_id" not in kwargs:
            kwargs["event_id"] = str(uuid.uuid4())
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "mission_id": self.mission_id,
            "chain_id": self.chain_id,
            "finding_id": self.finding_id,
            "hypothesis_id": self.hypothesis_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "event_type": self.event_type.value,
            "producer_role": self.producer_role,
            "receiver_role": self.receiver_role,
            "evidence_reference": self.evidence_reference,
            "authorization_reference": self.authorization_reference,
            "timestamp": self.timestamp,
            "status": self.status,
            "reason": self.reason,
            "source_engine": self.source_engine,
            "target_engine": self.target_engine,
            "depth": self.depth,
            "asset": self.asset,
            "outcome": self.outcome,
        }
