"""
HERMES-FINDING-CHAIN-001 — Cross-Gear Perspective Engine
==========================================================
Mandatory cross-gear interpretation. Every material finding is shared
with all 4 gears (scraping, mining, security, evidence). No chain may
be activated from a security-only interpretation.

MYC-CHAIN-INV-001 enforced: all 4 perspectives required before chaining.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
import uuid

from .finding_node import (
    FindingNode,
    FindingEdge,
    FindingNodeType,
    FindingEdgeType,
)

if TYPE_CHECKING:
    from .findings_graph import FindingsGraph


# ═══════════════════════════════════════════════════════════════
# Perspective data classes
# ═══════════════════════════════════════════════════════════════

class GearPerspective:
    """A single gear's interpretation of a finding."""

    def __init__(
        self,
        gear: str,
        summary: str,
        points: List[str],
        confidence_modifier: float = 0.0,
        requires_action: bool = False,
        suggested_action: Optional[str] = None,
    ):
        self.gear = gear
        self.summary = summary
        self.points = points
        self.confidence_modifier = confidence_modifier
        self.requires_action = requires_action
        self.suggested_action = suggested_action

    def to_dict(self) -> dict:
        return {
            "gear": self.gear,
            "summary": self.summary,
            "points": self.points,
            "confidence_modifier": self.confidence_modifier,
            "requires_action": self.requires_action,
            "suggested_action": self.suggested_action,
        }


class CrossGearPerspectiveResult:
    """Complete cross-gear perspective for a single finding."""

    def __init__(
        self,
        finding_id: str,
        perspectives: Dict[str, GearPerspective],
        generated_at: Optional[str] = None,
    ):
        self.finding_id = finding_id
        self.perspectives = perspectives
        self.generated_at = generated_at or datetime.now(timezone.utc).isoformat()

    @property
    def is_security_only(self) -> bool:
        """True if only the security gear contributed (anti-pattern)."""
        return set(self.perspectives.keys()) == {"security"}

    @property
    def gear_count(self) -> int:
        return len(self.perspectives)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "perspectives": {k: v.to_dict() for k, v in self.perspectives.items()},
            "generated_at": self.generated_at,
            "gear_count": self.gear_count,
            "is_security_only": self.is_security_only,
        }


# ═══════════════════════════════════════════════════════════════
# CrossGearPerspectiveEngine
# ═══════════════════════════════════════════════════════════════

class CrossGearPerspectiveEngine:
    """Generates mandatory cross-gear interpretations for every material finding.

    Every finding must be interpreted through all 4 gears:
    - Scraping: new routes/sources, extraction paths, data consistency, source reliability
    - Mining: new variables/datasets, population implications, baseline effects, controlled samples
    - Security: trust boundaries, authorization, potential vs confirmed, safe validation, blocked actions
    - Evidence: provenance, causation, contradictions, confidence, chain support

    Invariant: validate_perspectives() enforces that all 4 are present.
    No chain may be activated from a security-only interpretation.
    """

    REQUIRED_GEARS = {"scraping", "mining", "security", "evidence"}

    def __init__(self):
        self._results: Dict[str, CrossGearPerspectiveResult] = {}  # finding_id -> result
        self._security_only_blocked: int = 0

    # ── Public API ──────────────────────────────────────────────

    def generate_perspectives(
        self,
        finding: FindingNode,
        graph: "FindingsGraph",
    ) -> CrossGearPerspectiveResult:
        """Generate all 4 gear perspectives for a finding.

        Args:
            finding: The FindingNode to interpret.
            graph: The FindingsGraph for context (edges, related nodes, etc.).

        Returns:
            CrossGearPerspectiveResult with all 4 perspective keys populated.
        """
        # Collect context from the graph
        edges = graph.get_edges_for_node(finding.node_id)
        descendants = graph.get_descendants(finding.node_id, depth=3)

        perspectives: Dict[str, GearPerspective] = {}

        # ── 1. Scraping perspective ──
        perspectives["scraping"] = self._generate_scraping_perspective(
            finding, edges, descendants
        )

        # ── 2. Mining perspective ──
        perspectives["mining"] = self._generate_mining_perspective(
            finding, edges, descendants
        )

        # ── 3. Security perspective ──
        perspectives["security"] = self._generate_security_perspective(
            finding, edges, descendants
        )

        # ── 4. Evidence perspective ──
        perspectives["evidence"] = self._generate_evidence_perspective(
            finding, edges, descendants
        )

        result = CrossGearPerspectiveResult(
            finding_id=finding.node_id,
            perspectives=perspectives,
        )

        # Enforce: track security-only results
        if result.is_security_only:
            self._security_only_blocked += 1

        self._results[finding.node_id] = result
        return result

    def validate_perspectives(
        self,
        perspectives: Dict[str, GearPerspective],
    ) -> bool:
        """Validate that all 4 required gears are present.

        Returns True only when all of 'scraping', 'mining', 'security',
        and 'evidence' keys are present and non-None.
        """
        if not isinstance(perspectives, dict):
            return False

        present = set(perspectives.keys())
        return self.REQUIRED_GEARS.issubset(present)

    def can_activate_chain(self, result: CrossGearPerspectiveResult) -> bool:
        """Check if a chain can be activated from this perspective result.

        Returns False if the result is security-only (invariant: no chain
        may be activated from a security-only interpretation).
        """
        if not self.validate_perspectives(result.perspectives):
            return False
        if result.is_security_only:
            return False
        return True

    # ── Perspective generators ─────────────────────────────────

    def _generate_scraping_perspective(
        self,
        finding: FindingNode,
        edges: List["FindingEdge"],
        descendants: List[FindingNode],
    ) -> GearPerspective:
        """Scraping gear: new routes/sources, extraction paths, data consistency,
        source reliability."""
        points: List[str] = []

        # New routes/sources
        if finding.observed_fact:
            points.append(
                f"New data source observed: '{finding.observed_fact[:120]}'"
            )
        if finding.affected_assets:
            points.append(
                f"Affected assets: {', '.join(finding.affected_assets[:5])}"
            )

        # Extraction paths
        extraction_edges = [
            e for e in edges
            if e.edge_type in (FindingEdgeType.SUPPORTS, FindingEdgeType.MAY_ENABLE)
        ]
        if extraction_edges:
            points.append(
                f"Extraction paths: {len(extraction_edges)} edge(s) may enable "
                f"further data extraction"
            )
        else:
            points.append("No direct extraction paths identified from this finding")

        # Data consistency
        if finding.validation_status == "VALIDATED":
            points.append("Data consistency: finding has been validated — source data is consistent")
        elif finding.validation_status == "CONTRADICTED":
            points.append(
                "Data consistency: WARNING — finding is contradicted; "
                "source data may be inconsistent"
            )
        else:
            points.append(
                f"Data consistency: unvalidated ({finding.validation_status}) — "
                "source reliability not yet confirmed"
            )

        # Source reliability
        points.append(
            f"Source reliability: gear={finding.source_gear}, "
            f"agent={finding.source_agent_id}, confidence={finding.confidence:.2f}"
        )

        return GearPerspective(
            gear="scraping",
            summary=f"Scraping interpretation of finding '{finding.title}'",
            points=points,
            confidence_modifier=0.0,
        )

    def _generate_mining_perspective(
        self,
        finding: FindingNode,
        edges: List["FindingEdge"],
        descendants: List[FindingNode],
    ) -> GearPerspective:
        """Mining gear: new variables/datasets, population implications,
        baseline effects, controlled samples."""
        points: List[str] = []

        # New variables/datasets
        if finding.node_type == FindingNodeType.DATA_SOURCE:
            points.append(
                f"New dataset identified: '{finding.title}' — {finding.description[:150]}"
            )
        elif finding.node_type == FindingNodeType.OBSERVATION:
            points.append(
                f"New variable observed: '{finding.observed_fact[:120]}'"
            )
        else:
            points.append(
                f"Variable context: type={finding.node_type.value}, "
                f"relevance to mining: {finding.materiality}"
            )

        # Population implications
        if finding.materiality in ("high", "critical"):
            points.append(
                f"Population implication: HIGH — this finding affects a "
                f"material portion of the target population"
            )
        elif finding.materiality == "medium":
            points.append(
                "Population implication: MEDIUM — may affect a subset of the population"
            )
        else:
            points.append(
                "Population implication: LOW — limited population impact expected"
            )

        # Baseline effects
        if finding.confidence >= 0.8:
            points.append(
                f"Baseline effect: high-confidence finding (confidence={finding.confidence:.2f}) "
                "— suitable as a statistical baseline"
            )
        elif finding.confidence >= 0.5:
            points.append(
                f"Baseline effect: moderate confidence (confidence={finding.confidence:.2f}) "
                "— use with caution as baseline"
            )
        else:
            points.append(
                f"Baseline effect: low confidence (confidence={finding.confidence:.2f}) "
                "— NOT suitable as baseline without additional validation"
            )

        # Controlled samples
        if finding.evidence_ids:
            points.append(
                f"Controlled samples: {len(finding.evidence_ids)} evidence item(s) "
                "available for sample verification"
            )
        else:
            points.append(
                "Controlled samples: no evidence attached — cannot verify sampling"
            )

        return GearPerspective(
            gear="mining",
            summary=f"Mining interpretation of finding '{finding.title}'",
            points=points,
            confidence_modifier=0.0,
        )

    def _generate_security_perspective(
        self,
        finding: FindingNode,
        edges: List["FindingEdge"],
        descendants: List[FindingNode],
    ) -> GearPerspective:
        """Security gear: trust boundaries, authorization, potential vs confirmed,
        safe validation, blocked actions."""
        points: List[str] = []
        requires_action = False

        # Trust boundaries
        if finding.affected_trust_boundaries:
            points.append(
                f"Trust boundaries crossed: {', '.join(finding.affected_trust_boundaries)}"
            )
        else:
            points.append("Trust boundaries: none directly affected by this finding")

        # Authorization status
        points.append(f"Authorization status: {finding.authorization_status}")

        # Potential vs confirmed
        if finding.validation_status == "VALIDATED":
            points.append("Status: CONFIRMED — finding has been validated")
        elif finding.validation_status == "IN_PROGRESS":
            points.append("Status: IN PROGRESS — validation underway, treat as potential")
        elif finding.validation_status == "REJECTED":
            points.append("Status: REJECTED — finding was not substantiated")
        else:
            points.append(
                f"Status: POTENTIAL — finding is {finding.validation_status}, "
                "requires validation before acting"
            )

        # Safe validation options
        if finding.node_type == FindingNodeType.HYPOTHESIS:
            safe_edges = [
                e for e in edges
                if e.edge_type == FindingEdgeType.VALIDATED_BY
            ]
            if safe_edges:
                points.append(
                    f"Safe validation available: {len(safe_edges)} validation path(s) exist"
                )
            else:
                points.append(
                    "Safe validation: no validated-by edges found — "
                    "exercise caution before testing"
                )
        else:
            points.append(
                "Safe validation: finding is not a hypothesis — "
                "direct observation; validate supporting evidence"
            )

        # Blocked actions
        blocked_edges = [
            e for e in edges if e.edge_type == FindingEdgeType.BLOCKED_BY
        ]
        if blocked_edges:
            requires_action = True
            points.append(
                f"Blocked actions: {len(blocked_edges)} blocked edge(s) — "
                "review authorization before proceeding"
            )
        else:
            points.append("Blocked actions: no blocks detected")

        return GearPerspective(
            gear="security",
            summary=f"Security interpretation of finding '{finding.title}'",
            points=points,
            confidence_modifier=0.0,
            requires_action=requires_action,
            suggested_action=(
                "Review blocked edges and obtain required authorization"
                if requires_action else None
            ),
        )

    def _generate_evidence_perspective(
        self,
        finding: FindingNode,
        edges: List["FindingEdge"],
        descendants: List[FindingNode],
    ) -> GearPerspective:
        """Evidence gear: provenance, causation, contradictions, confidence,
        chain support."""
        points: List[str] = []

        # Provenance
        points.append(
            f"Provenance: produced by {finding.source_gear} gear, "
            f"agent {finding.source_agent_id}, "
            f"at {finding.created_at}"
        )
        if finding.approving_manager_id:
            points.append(
                f"Approval provenance: approved by manager {finding.approving_manager_id}"
            )

        # Causation
        causation_edges = [
            e for e in edges
            if e.edge_type in (
                FindingEdgeType.SUPPORTS,
                FindingEdgeType.VALIDATED_BY,
                FindingEdgeType.AFFECTS,
            )
        ]
        if causation_edges:
            points.append(
                f"Causation: {len(causation_edges)} causation edge(s) — "
                f"types: {', '.join(set(e.edge_type.value for e in causation_edges))}"
            )
        else:
            points.append("Causation: no direct causation edges — correlation only")

        # Contradictions
        contradiction_edges = [
            e for e in edges if e.edge_type == FindingEdgeType.CONTRADICTS
        ]
        if contradiction_edges:
            points.append(
                f"Contradictions: {len(contradiction_edges)} contradiction(s) detected — "
                "chain support may be undermined"
            )
        else:
            points.append("Contradictions: none detected")

        # Confidence
        if finding.confidence >= 0.9:
            conf_label = "VERY HIGH"
        elif finding.confidence >= 0.7:
            conf_label = "HIGH"
        elif finding.confidence >= 0.5:
            conf_label = "MODERATE"
        elif finding.confidence >= 0.3:
            conf_label = "LOW"
        else:
            conf_label = "VERY LOW"
        points.append(f"Confidence: {conf_label} ({finding.confidence:.2f})")

        # Chain support
        chain_edges = [
            e for e in edges
            if e.edge_type in (
                FindingEdgeType.SUPPORTS,
                FindingEdgeType.MAY_ENABLE,
                FindingEdgeType.VALIDATED_BY,
            )
        ]
        if chain_edges:
            points.append(
                f"Chain support: {len(chain_edges)} edge(s) support chain linkage"
            )
        else:
            points.append(
                "Chain support: no supporting edges — finding is isolated"
            )

        return GearPerspective(
            gear="evidence",
            summary=f"Evidence interpretation of finding '{finding.title}'",
            points=points,
            confidence_modifier=0.0,
        )

    # ── Query / cache ──────────────────────────────────────────

    def get_result(self, finding_id: str) -> Optional[CrossGearPerspectiveResult]:
        """Retrieve a previously generated perspective result."""
        return self._results.get(finding_id)

    def get_all_results(self) -> Dict[str, CrossGearPerspectiveResult]:
        """Return all generated perspective results."""
        return dict(self._results)

    def get_security_only_count(self) -> int:
        """Return the number of security-only results that were blocked."""
        return self._security_only_blocked

    def clear(self) -> None:
        """Clear all cached results."""
        self._results.clear()
        self._security_only_blocked = 0
