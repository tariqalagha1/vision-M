"""
HERMES-PARALLEL-DISCOVERY-001 — Gear Perspective Engines
Each gear independently analyzes a discovery from its domain perspective.
No gear waits for another. All perspectives are manager-reviewable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

# ── Import discovery_types (or fallback) ──────────────────────────────
try:
    from .discovery_types import (
        DiscoveryPerspective,
        PerspectiveStatus,
        DiscoveryRecord,
    )
except ImportError:
    # ═══════════════════════════════════════════════════════════════
    # FALLBACK — discovery_types not yet built by companion subagent
    # ═══════════════════════════════════════════════════════════════
    from enum import Enum
    from dataclasses import dataclass, field

    class PerspectiveStatus(str, Enum):
        CREATED = "CREATED"
        UNDER_ANALYSIS = "UNDER_ANALYSIS"
        SUBMITTED_TO_MANAGER = "SUBMITTED_TO_MANAGER"
        REWORK_REQUIRED = "REWORK_REQUIRED"
        MANAGER_APPROVED = "MANAGER_APPROVED"
        MANAGER_REJECTED = "MANAGER_REJECTED"
        TIMED_OUT = "TIMED_OUT"
        ESCALATED = "ESCALATED"

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
        version: int = 1
        previous_version_id: Optional[str] = None

        @classmethod
        def create(cls, **kwargs) -> "DiscoveryPerspective":
            if "perspective_id" not in kwargs:
                kwargs["perspective_id"] = str(uuid.uuid4())
            if "created_at" not in kwargs:
                kwargs["created_at"] = datetime.now(timezone.utc).isoformat()
            if "status" not in kwargs:
                kwargs["status"] = PerspectiveStatus.CREATED.value
            return cls(**kwargs)

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
        status: str
        created_at: str
        updated_at: str
        broadcast_at: Optional[str] = None

        @classmethod
        def create(cls, **kwargs) -> "DiscoveryRecord":
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


# ═══════════════════════════════════════════════════════════════
# Base engine
# ═══════════════════════════════════════════════════════════════

class BaseGearEngine(ABC):
    """Abstract base for all gear analysis engines."""

    @property
    @abstractmethod
    def gear_name(self) -> str: ...

    @abstractmethod
    def analyze(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        evidence_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryPerspective:
        """Analyze a discovery from this gear's perspective.

        Args:
            discovery: The DiscoveryRecord to analyze
            agent_id: ID of the agent performing analysis
            evidence_context: Additional evidence for the analysis

        Returns:
            A DiscoveryPerspective with this gear's complete analysis
        """
        ...

    def _create_perspective(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        interpretation: str,
        opportunities: List[str],
        risks: List[str],
        uncertainties: List[str],
        contradictions: List[str],
        recommended_actions: List[str],
        operational_impact: str,
        data_acquisition_impact: str,
        mining_impact: str,
        security_impact: str,
        scope_impact: str,
        authorization_impact: str,
        confidence: float,
        evidence_ids: Optional[List[str]] = None,
    ) -> DiscoveryPerspective:
        """Factory for creating perspectives with common defaults."""
        return DiscoveryPerspective.create(
            discovery_id=discovery.discovery_id,
            mission_id=discovery.mission_id,
            correlation_id=discovery.correlation_id,
            gear=self.gear_name,
            producing_agent_id=agent_id,
            approving_manager_id="",
            interpretation=interpretation,
            evidence_ids=evidence_ids or discovery.evidence_references,
            opportunities=opportunities,
            risks=risks,
            uncertainties=uncertainties,
            contradictions=contradictions,
            recommended_actions=recommended_actions,
            operational_impact=operational_impact,
            data_acquisition_impact=data_acquisition_impact,
            mining_impact=mining_impact,
            security_impact=security_impact,
            scope_impact=scope_impact,
            authorization_impact=authorization_impact,
            confidence=confidence,
            status=PerspectiveStatus.CREATED.value,
        )

    def start_analysis(self, perspective: DiscoveryPerspective) -> DiscoveryPerspective:
        """Mark a perspective as under analysis."""
        perspective.status = PerspectiveStatus.UNDER_ANALYSIS.value
        return perspective


# ═══════════════════════════════════════════════════════════════
# Scraping Gear Engine
# ═══════════════════════════════════════════════════════════════

class ScrapingGearEngine(BaseGearEngine):
    """Scraping gear: Evaluates new source value, extraction strategy,
    API vs DOM reliability, pagination, normalization, re-scraping
    requirements, source stability, and acquisition risks.

    Per Section 5 of the mission spec.
    """

    @property
    def gear_name(self) -> str:
        return "scraping"

    def analyze(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        evidence_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryPerspective:
        ctx = evidence_context or {}
        types = set(discovery.discovery_types)

        # Build interpretation
        interpretation_parts = []
        opportunities = []
        risks = []
        uncertainties = []
        contradictions = []
        recommended_actions = []

        # NEW SOURCE VALUE
        if "API_DISCOVERY" in types or "STRUCTURED_CATALOG" in types:
            interpretation_parts.append(
                f"New data source identified: {discovery.title}. "
                f"Materiality: {discovery.materiality}."
            )
            opportunities.append(
                "Structured acquisition opportunity — API-based extraction reduces DOM dependency"
            )
            opportunities.append(
                "Potential for high-volume structured data acquisition with minimal parsing overhead"
            )
        elif "DATA_SOURCE" in types:
            interpretation_parts.append(
                f"New data source discovered: {discovery.title}"
            )
            opportunities.append(
                "Unstructured or semi-structured data source requiring parsing strategy"
            )
        elif "ENDPOINT" in types:
            interpretation_parts.append(
                f"New endpoint identified: {discovery.title}"
            )
            opportunities.append(
                "Specific endpoint may expose additional API surface"
            )
        else:
            interpretation_parts.append(
                f"Discovery type {discovery.discovery_types} — "
                f"scraping relevance: {discovery.materiality}"
            )

        # EXTRACTION STRATEGY
        if "API_DISCOVERY" in types or "STRUCTURED_CATALOG" in types:
            interpretation_parts.append(
                "API-based extraction strategy recommended. "
                "Lower overhead than DOM parsing. "
                "Pagination behavior must be assessed."
            )
            opportunities.append(
                "Schema-driven extraction — reliable field mapping"
            )
            uncertainties.append(
                "API pagination behavior and rate limits unknown — requires testing"
            )
            uncertainties.append(
                "Schema completeness not verified — fields may be missing or deprecated"
            )
            recommended_actions.append(
                "Map API schema — identify all available fields and data types"
            )
            recommended_actions.append(
                "Test pagination — determine page size, total pages, rate limits"
            )
        else:
            interpretation_parts.append(
                "DOM-based or hybrid extraction strategy likely required. "
                "May need CSS/XPath selectors."
            )
            uncertainties.append(
                "DOM structure stability unknown — selectors may break on site changes"
            )
            recommended_actions.append(
                "Audit DOM structure — identify stable CSS selectors for extraction"
            )

        # API vs DOM RELIABILITY
        if "API_DISCOVERY" in types or "STRUCTURED_CATALOG" in types:
            interpretation_parts.append(
                "API reliability: expected HIGH — structured endpoints have predictable behavior"
            )
        else:
            interpretation_parts.append(
                "Reliability: DOM-dependent — may vary with site redesigns"
            )
            risks.append(
                "DOM-based extraction is fragile — site redesigns break selectors"
            )

        # NORMALIZATION IMPACT
        interpretation_parts.append(
            "Normalization impact: new source requires field mapping, "
            "type coercion, and deduplication pipeline integration"
        )
        recommended_actions.append(
            "Define normalization schema — map source fields to canonical model"
        )

        # RE-SCRAPING REQUIREMENTS
        if discovery.materiality in ("high", "critical"):
            interpretation_parts.append(
                "Re-scraping: recommended at regular intervals due to high materiality"
            )
            recommended_actions.append(
                "Schedule recurring scrape — high materiality warrants freshness"
            )

        # SOURCE STABILITY / ACQUISITION RISKS
        risks.append(
            "Source may change structure, rate-limit, or become unavailable"
        )
        risks.append(
            "Authentication or session management may be required for sustained access"
        )
        uncertainties.append(
            "Source longevity unknown — evaluate historical availability"
        )

        # DATA-FIELD AVAILABILITY
        interpretation_parts.append(
            "Data-field availability: must enumerate all available fields "
            "and identify gaps against target schema"
        )

        interpretation = ". ".join(interpretation_parts) + "."

        return self._create_perspective(
            discovery=discovery,
            agent_id=agent_id,
            interpretation=interpretation,
            opportunities=opportunities,
            risks=risks,
            uncertainties=uncertainties,
            contradictions=contradictions,
            recommended_actions=recommended_actions,
            operational_impact=(
                "New scraping pipeline required — scheduler, parser, "
                "normalizer, and error handler"
            ),
            data_acquisition_impact=(
                "Increases data acquisition surface — new structured source available"
            ),
            mining_impact="Enables structured data mining with schema-aware extraction",
            security_impact=(
                "Acquisition scope must be authorized — verify access permissions"
            ),
            scope_impact=(
                "Expands data acquisition scope — requires Program Manager approval"
            ),
            authorization_impact=(
                "May require additional authorization for sustained/production scraping"
            ),
            confidence=0.75,
            evidence_ids=discovery.evidence_references,
        )


# ═══════════════════════════════════════════════════════════════
# Mining Gear Engine
# ═══════════════════════════════════════════════════════════════

class MiningGearEngine(BaseGearEngine):
    """Mining gear: Evaluates historical-data opportunity, baseline creation,
    trend-analysis potential, association and clustering opportunities,
    candidate variables, data sufficiency, bias and quality limitations,
    commercial or operational intelligence value, and required validation
    datasets.

    Per Section 5 of the mission spec.
    """

    @property
    def gear_name(self) -> str:
        return "mining"

    def analyze(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        evidence_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryPerspective:
        ctx = evidence_context or {}
        types = set(discovery.discovery_types)

        interpretation_parts = []
        opportunities = []
        risks = []
        uncertainties = []
        contradictions = []
        recommended_actions = []

        # HISTORICAL DATA OPPORTUNITY
        if "STRUCTURED_CATALOG" in types:
            interpretation_parts.append(
                f"Product history opportunity: {discovery.title} provides "
                "structured catalog data suitable for historical trend analysis"
            )
            opportunities.append(
                "Pricing trend analysis — track price changes over time"
            )
            opportunities.append(
                "Inventory trend analysis — monitor stock levels and availability"
            )
            opportunities.append(
                "Product lifecycle analysis — introduction, growth, maturity, decline patterns"
            )
        elif "API_DISCOVERY" in types:
            interpretation_parts.append(
                f"Data opportunity: {discovery.title} may expose structured data "
                "suitable for mining operations"
            )
            opportunities.append(
                "Pattern discovery — identify associations, clusters, outliers"
            )
        else:
            interpretation_parts.append(
                f"Data mining relevance: {discovery.materiality} — "
                "assess data sufficiency before committing mining resources"
            )

        # BASELINE CREATION
        verb = "robust" if discovery.materiality in ("high", "critical") else "targeted"
        label = "HIGH" if discovery.materiality in ("high", "critical") else "MEDIUM"
        interpretation_parts.append(
            f"Baseline creation potential: {label} — "
            f"discovery materiality supports {verb} baseline"
        )
        if discovery.materiality in ("high", "critical"):
            recommended_actions.append(
                "Establish statistical baseline from initial sample"
            )

        # ASSOCIATION AND CLUSTERING
        if "STRUCTURED_CATALOG" in types or "API_DISCOVERY" in types:
            opportunities.append(
                "Association mining — product co-occurrence, category relationships"
            )
            opportunities.append(
                "Clustering — segment products by price, category, availability patterns"
            )

        # CANDIDATE VARIABLES
        interpretation_parts.append(
            "Candidate variables: price, category, availability, timestamp, "
            "product attributes — subject to actual field availability"
        )

        # DATA SUFFICIENCY
        if discovery.materiality in ("high", "critical"):
            interpretation_parts.append(
                "Data sufficiency: expected SUFFICIENT given high materiality"
            )
        else:
            interpretation_parts.append(
                "Data sufficiency: UNKNOWN — must validate data volume "
                "and completeness before mining"
            )
            uncertainties.append(
                "Data volume unknown — insufficient volume degrades mining value"
            )

        # BIAS AND QUALITY
        risks.append("Selection bias — data may not represent full population")
        risks.append(
            "Temporal bias — historical data may not reflect current patterns"
        )
        uncertainties.append(
            "Data quality not assessed — missing values, duplicates, "
            "inconsistencies possible"
        )
        recommended_actions.append(
            "Assess data quality — completeness, consistency, accuracy metrics"
        )

        # COMMERCIAL/OPERATIONAL INTELLIGENCE VALUE
        if discovery.materiality in ("high", "critical"):
            interpretation_parts.append(
                "Commercial intelligence value: HIGH — structured catalog data "
                "provides actionable market intelligence"
            )
            opportunities.append(
                "Competitive intelligence — pricing, assortment, and availability analysis"
            )

        # REQUIRED VALIDATION DATASETS
        recommended_actions.append(
            "Identify validation dataset — holdout sample for model verification"
        )
        recommended_actions.append(
            "Cross-reference with existing data — detect overlaps and gaps"
        )

        interpretation = ". ".join(interpretation_parts) + "."

        return self._create_perspective(
            discovery=discovery,
            agent_id=agent_id,
            interpretation=interpretation,
            opportunities=opportunities,
            risks=risks,
            uncertainties=uncertainties,
            contradictions=contradictions,
            recommended_actions=recommended_actions,
            operational_impact=(
                "Requires data ingestion pipeline, quality assessment, "
                "and mining job scheduling"
            ),
            data_acquisition_impact=(
                "Mining depends on successful data acquisition — "
                "coupled with scraping output"
            ),
            mining_impact=(
                "Enables product intelligence, trend analysis, and "
                "competitive benchmarking"
            ),
            security_impact=(
                "Mined data must be protected — sensitivity classification required"
            ),
            scope_impact="Extends mining scope — new data domain for the mining pipeline",
            authorization_impact=(
                "Standard mining authorization — no elevated privileges required"
            ),
            confidence=0.65,
            evidence_ids=discovery.evidence_references,
        )


# ═══════════════════════════════════════════════════════════════
# Security Gear Engine
# ═══════════════════════════════════════════════════════════════

class SecurityGearEngine(BaseGearEngine):
    """Security gear: Evaluates authorization, scope, intended public exposure,
    potential versus confirmed weakness, data-sensitivity implications,
    safe follow-up boundaries, required approval, severity calibration,
    and prohibited actions.

    Per Section 5 of the mission spec. CRITICAL: Public access is NOT
    automatically a vulnerability. Security may block unsafe execution
    but must NOT replace scraping, mining, or evidence analysis.
    """

    @property
    def gear_name(self) -> str:
        return "security"

    def analyze(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        evidence_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryPerspective:
        ctx = evidence_context or {}
        types = set(discovery.discovery_types)

        interpretation_parts = []
        opportunities = []
        risks = []
        uncertainties = []
        contradictions = []
        recommended_actions = []

        # AUTHORIZATION
        interpretation_parts.append(
            "Authorization: discovery does not itself constitute a security finding. "
            "Public API/catalog access is NOT automatically a vulnerability."
        )

        # PUBLIC EXPOSURE
        if "API_DISCOVERY" in types or "STRUCTURED_CATALOG" in types:
            interpretation_parts.append(
                "Public API/catalog exposure: access appears intentional. "
                "Security analysis must distinguish between authorized public interfaces "
                "and unintended information exposure."
            )
            # Key invariant: public API ≠ vulnerability
            risks.append(
                "UNCONFIRMED — API is publicly accessible but this does not "
                "constitute a confirmed weakness. Further security testing "
                "requires separate authorization."
            )

        # POTENTIAL VS CONFIRMED
        interpretation_parts.append(
            "Status: POTENTIAL — no confirmed weakness. "
            "This is a discovery, not a security finding. "
            "Any security testing beyond passive observation requires "
            "explicit authorization."
        )
        uncertainties.append(
            "Without authorized security testing, weakness status remains POTENTIAL only"
        )

        # DATA SENSITIVITY
        if discovery.materiality in ("high", "critical"):
            interpretation_parts.append(
                "Data sensitivity: requires classification review — "
                "high-materiality data may contain sensitive information"
            )
            risks.append(
                "Data sensitivity not classified — potential information "
                "exposure if improperly handled"
            )

        # SAFE FOLLOW-UP BOUNDARIES
        interpretation_parts.append(
            "Safe follow-up: passive observation only. "
            "Active testing, credential attempts, or scope expansion "
            "REQUIRES explicit security authorization."
        )
        recommended_actions.append(
            "Classify data sensitivity before any further action"
        )
        recommended_actions.append(
            "Obtain security authorization for any active testing"
        )

        # SEVERITY CALIBRATION
        interpretation_parts.append(
            f"Severity: INFO — discovery is intelligence, not vulnerability. "
            f"Materiality: {discovery.materiality}."
        )

        # PROHIBITED ACTIONS
        interpretation_parts.append(
            "PROHIBITED: Unauthorized security testing, credential brute-forcing, "
            "scope expansion, external system probing, production impact testing"
        )

        interpretation = ". ".join(interpretation_parts) + "."

        return self._create_perspective(
            discovery=discovery,
            agent_id=agent_id,
            interpretation=interpretation,
            opportunities=opportunities,
            risks=risks,
            uncertainties=uncertainties,
            contradictions=contradictions,
            recommended_actions=recommended_actions,
            operational_impact=(
                "Security review required before operational deployment. "
                "No active security testing without separate authorization."
            ),
            data_acquisition_impact=(
                "Security review of data acquisition boundaries — "
                "verify authorized scope"
            ),
            mining_impact="No direct mining impact — security gate, not mining gate",
            security_impact=(
                "Discovery intelligence only. Public access is NOT a vulnerability. "
                "Security authorization restrictions remain binding."
            ),
            scope_impact=(
                "Scope change requires security approval — no automatic scope expansion"
            ),
            authorization_impact=(
                "Authorization restrictions remain binding. Security review "
                "must not replace scraping, mining, or evidence analysis."
            ),
            confidence=0.85,
            evidence_ids=discovery.evidence_references,
        )


# ═══════════════════════════════════════════════════════════════
# Evidence Gear Engine
# ═══════════════════════════════════════════════════════════════

class EvidenceGearEngine(BaseGearEngine):
    """Evidence gear: Evaluates provenance, source reliability, evidence
    completeness, cross-source concordance, contradictions, confidence,
    version and timestamp integrity, and whether the discovery is
    sufficiently verified.

    Per Section 5 of the mission spec.
    """

    @property
    def gear_name(self) -> str:
        return "evidence"

    def analyze(
        self,
        discovery: DiscoveryRecord,
        agent_id: str,
        evidence_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryPerspective:
        ctx = evidence_context or {}

        interpretation_parts = []
        opportunities = []
        risks = []
        uncertainties = []
        contradictions = []
        recommended_actions = []

        # PROVENANCE
        interpretation_parts.append(
            f"Provenance: discovered by {discovery.source_gear} gear, "
            f"agent {discovery.source_agent_id}, "
            f"manager {discovery.source_manager_id}"
        )
        interpretation_parts.append(
            f"Timestamp: {discovery.created_at} — "
            "version and timestamp integrity: PRESERVED"
        )

        # SOURCE RELIABILITY
        source_confidence = (
            "HIGH" if discovery.source_gear in ("scraping", "security") else "MODERATE"
        )
        interpretation_parts.append(
            f"Source reliability: {source_confidence} — "
            f"produced by {discovery.source_gear} gear"
        )
        if source_confidence != "HIGH":
            uncertainties.append(
                f"Source gear ({discovery.source_gear}) reliability not "
                "independently validated"
            )

        # EVIDENCE COMPLETENESS
        if discovery.evidence_references:
            interpretation_parts.append(
                f"Evidence completeness: {len(discovery.evidence_references)} "
                f"reference(s) attached — "
                f"{'SUFFICIENT for initial assessment' if len(discovery.evidence_references) >= 1 else 'INSUFFICIENT'}"
            )
        else:
            interpretation_parts.append(
                "Evidence completeness: INSUFFICIENT — no evidence references attached"
            )
            risks.append(
                "No corroborating evidence — discovery is unverified assertion"
            )
            recommended_actions.append(
                "Attach supporting evidence — screenshots, logs, response dumps"
            )

        # CROSS-SOURCE CONCORDANCE
        if len(discovery.evidence_references) >= 2:
            interpretation_parts.append(
                "Cross-source concordance: multiple evidence references available — "
                "concordance assessment pending"
            )
            recommended_actions.append(
                "Cross-reference all evidence sources for consistency"
            )
        else:
            uncertainties.append(
                "Single source of evidence — cannot assess cross-source concordance"
            )

        # CONTRADICTIONS
        interpretation_parts.append(
            "Contradictions: none detected at initial evidence review — "
            "awaiting cross-gear perspective comparison"
        )

        # CONFIDENCE
        interpretation_parts.append(
            f"Evidence confidence: {discovery.materiality.upper()} materiality suggests "
            f"{'thorough' if discovery.materiality in ('high', 'critical') else 'standard'} "
            "evidence review warranted"
        )

        # IS DISCOVERY SUFFICIENTLY VERIFIED?
        if discovery.evidence_references:
            interpretation_parts.append(
                "Verification status: partially verified — evidence exists but "
                "cross-gear perspectives required for full verification"
            )
        else:
            interpretation_parts.append(
                "Verification status: NOT VERIFIED — insufficient evidence for confidence"
            )
            uncertainties.append(
                "Discovery is unverified — confidence cannot exceed LOW without evidence"
            )

        interpretation = ". ".join(interpretation_parts) + "."

        return self._create_perspective(
            discovery=discovery,
            agent_id=agent_id,
            interpretation=interpretation,
            opportunities=opportunities,
            risks=risks,
            uncertainties=uncertainties,
            contradictions=contradictions,
            recommended_actions=recommended_actions,
            operational_impact=(
                "Evidence quality directly impacts downstream decision confidence"
            ),
            data_acquisition_impact=(
                "Evidence integrity must be validated before data enters mining pipeline"
            ),
            mining_impact=(
                "Poor evidence quality degrades mining results — garbage in, garbage out"
            ),
            security_impact=(
                "Evidence of security relevance must be flagged for security gear review"
            ),
            scope_impact=(
                "Evidence scope defines the boundary of what is known vs assumed"
            ),
            authorization_impact=(
                "Evidence supporting authorization claims must be independently verified"
            ),
            confidence=0.55 if discovery.evidence_references else 0.30,
            evidence_ids=discovery.evidence_references,
        )


# ═══════════════════════════════════════════════════════════════
# Engine Registry
# ═══════════════════════════════════════════════════════════════

class GearEngineRegistry:
    """Registry of all gear analysis engines."""

    def __init__(self):
        self._engines: Dict[str, BaseGearEngine] = {
            "scraping": ScrapingGearEngine(),
            "mining": MiningGearEngine(),
            "security": SecurityGearEngine(),
            "evidence": EvidenceGearEngine(),
        }

    def get_engine(self, gear: str) -> BaseGearEngine:
        """Get the engine for a specific gear."""
        engine = self._engines.get(gear)
        if not engine:
            raise ValueError(
                f"Unknown gear: {gear}. Available: {list(self._engines.keys())}"
            )
        return engine

    def get_all_engines(self) -> Dict[str, BaseGearEngine]:
        """Get all registered engines."""
        return dict(self._engines)

    @property
    def required_gears(self) -> List[str]:
        return sorted(self._engines.keys())
