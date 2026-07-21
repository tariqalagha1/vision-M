"""
HERMES-PARALLEL-DISCOVERY-001 — Evidence Integration Synthesis
After the perspective gate passes, the Evidence Integration Manager
produces a structured synthesis that connects evidence, explains
dependencies, and preserves disagreement.

Per Section 10 of the mission spec.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .discovery_types import (
    DiscoveryPerspective, SynthesisResult,
)
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class EvidenceSynthesisEngine:
    """Structured evidence synthesis engine.

    Does NOT merely concatenate the four perspective reports.
    Connects evidence, explains dependencies, and preserves disagreement.

    Produces:
    - What each gear established
    - Areas of agreement
    - Areas of contradiction
    - Unresolved uncertainty
    - Scope implications
    - Authorization implications
    - Safe options
    - Blocked options
    - Recommended next-phase options
    """

    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._syntheses: Dict[str, SynthesisResult] = {}  # discovery_id -> synthesis

    def synthesize(
        self,
        discovery_id: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
        perspectives: List[DiscoveryPerspective],
        contradictions: Optional[List[dict]] = None,
        evidence_manager_id: str = "EVIDENCE_INTEGRATION_MANAGER",
    ) -> SynthesisResult:
        """Produce a structured synthesis from all approved perspectives.

        Args:
            discovery_id: The discovery being synthesized
            mission_id: Mission context
            correlation_id: Correlation for events
            causation_id: Causation for events
            perspectives: All manager-approved perspectives
            contradictions: Registered contradictions
            evidence_manager_id: The Evidence Integration Manager

        Returns:
            SynthesisResult with complete synthesis
        """
        # Emit synthesis started
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_SYNTHESIS_STARTED,
            discovery_id=discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=evidence_manager_id,
            receiver="ALL",
            gear="evidence",
            manager=evidence_manager_id,
            evidence_reference="",
        ))

        # Group perspectives by gear
        by_gear = {p.gear: p for p in perspectives}

        scraping = by_gear.get("scraping")
        mining = by_gear.get("mining")
        security = by_gear.get("security")
        evidence = by_gear.get("evidence")

        # ── What each gear established ──
        scraping_established = self._extract_established(scraping, "Scraping")
        mining_established = self._extract_established(mining, "Mining")
        security_established = self._extract_established(security, "Security")
        evidence_established = self._extract_established(evidence, "Evidence")

        # ── Areas of agreement ──
        areas_of_agreement = self._find_agreement(perspectives)

        # ── Areas of contradiction ──
        areas_of_contradiction = self._find_contradictions(
            perspectives, contradictions or []
        )

        # ── Unresolved uncertainty ──
        unresolved_uncertainty = self._collect_uncertainties(perspectives)

        # ── Scope implications ──
        scope_implications = self._synthesize_scope(perspectives)

        # ── Authorization implications ──
        authorization_implications = self._synthesize_authorization(perspectives)

        # ── Safe options ──
        safe_options = self._identify_safe_options(perspectives)

        # ── Blocked options ──
        blocked_options = self._identify_blocked_options(perspectives)

        # ── Recommended next-phase options ──
        recommended_options = self._recommend_next_phase(perspectives)

        synthesis = SynthesisResult.create(
            discovery_id=discovery_id,
            mission_id=mission_id,
            scraping_established=scraping_established,
            mining_established=mining_established,
            security_established=security_established,
            evidence_established=evidence_established,
            areas_of_agreement=areas_of_agreement,
            areas_of_contradiction=areas_of_contradiction,
            unresolved_uncertainty=unresolved_uncertainty,
            scope_implications=scope_implications,
            authorization_implications=authorization_implications,
            safe_options=safe_options,
            blocked_options=blocked_options,
            recommended_next_phase_options=recommended_options,
            produced_by=evidence_manager_id,
        )

        self._syntheses[discovery_id] = synthesis

        # Emit synthesis completed
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_SYNTHESIS_COMPLETED,
            discovery_id=discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=evidence_manager_id,
            receiver="ALL",
            gear="evidence",
            manager=evidence_manager_id,
            evidence_reference=synthesis.synthesis_id,
            data={
                "agreement_count": len(areas_of_agreement),
                "contradiction_count": len(areas_of_contradiction),
                "safe_option_count": len(safe_options),
                "blocked_option_count": len(blocked_options),
            },
        ))

        return synthesis

    def _extract_established(
        self,
        perspective: Optional[DiscoveryPerspective],
        gear_label: str,
    ) -> str:
        """Extract what a specific gear established."""
        if not perspective:
            return f"{gear_label}: No perspective available."

        lines = [
            f"{gear_label} established:",
            f"- Interpretation: {perspective.interpretation[:300]}",
            f"- Confidence: {perspective.confidence:.2f}",
        ]

        if perspective.opportunities:
            lines.append(f"- Opportunities: {', '.join(perspective.opportunities[:3])}")
        if perspective.risks:
            lines.append(f"- Risks: {', '.join(perspective.risks[:3])}")
        if perspective.recommended_actions:
            lines.append(f"- Recommended actions: {', '.join(perspective.recommended_actions[:3])}")

        return "\n".join(lines)

    def _find_agreement(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> List[str]:
        """Find areas where gears agree."""
        agreements = []

        # All agree discovery is material
        high_confs = [p for p in perspectives if p.confidence >= 0.5]
        if len(high_confs) >= 3:
            agreements.append(
                f"Majority of gears ({len(high_confs)}/{len(perspectives)}) "
                f"assess discovery with confidence >= 0.5"
            )

        # Check if scraping/mining agree on structured data
        scraping = next((p for p in perspectives if p.gear == "scraping"), None)
        mining = next((p for p in perspectives if p.gear == "mining"), None)
        if scraping and mining:
            if "structured" in scraping.interpretation.lower() and "structured" in mining.interpretation.lower():
                agreements.append(
                    "Scraping and Mining concur: discovery provides structured data opportunity"
                )

        # Check if security/evidence agree on NOT automatic vulnerability
        security = next((p for p in perspectives if p.gear == "security"), None)
        evidence_p = next((p for p in perspectives if p.gear == "evidence"), None)
        if security and evidence_p:
            if ("not automatically a vulnerability" in security.interpretation.lower() or
                "not a vulnerability" in security.interpretation.lower()):
                agreements.append(
                    "Security confirms: public access does not constitute vulnerability"
                )

        # At least one agreement always
        if not agreements:
            agreements.append("All gears acknowledge discovery requires further analysis")

        return agreements

    def _find_contradictions(
        self,
        perspectives: List[DiscoveryPerspective],
        registered: List[dict],
    ) -> List[str]:
        """Find and preserve contradictions between gear perspectives."""
        contradictions = []

        # Check for security trying to dominate
        security = next((p for p in perspectives if p.gear == "security"), None)
        scraping = next((p for p in perspectives if p.gear == "scraping"), None)

        if security and scraping:
            # Security might recommend blocking, scraping recommends action
            sec_blocks = "prohibited" in security.interpretation.lower()
            scrape_acts = scraping.recommended_actions and len(scraping.recommended_actions) > 0
            if sec_blocks and scrape_acts:
                contradictions.append(
                    "TENSION: Security emphasizes prohibited actions while "
                    "Scraping recommends active data acquisition. "
                    "Resolution: Scraping actions must be authorized per security boundaries."
                )

        # Evidence vs Mining confidence
        evidence_p = next((p for p in perspectives if p.gear == "evidence"), None)
        mining = next((p for p in perspectives if p.gear == "mining"), None)
        if evidence_p and mining:
            if evidence_p.confidence < 0.5 and mining.confidence > 0.6:
                contradictions.append(
                    f"DIVERGENCE: Evidence confidence ({evidence_p.confidence:.2f}) "
                    f"is significantly lower than Mining confidence ({mining.confidence:.2f}). "
                    f"Mining optimism may not be supported by evidence quality."
                )

        # Registered contradictions
        for c in registered:
            contradictions.append(
                f"REGISTERED: {c.get('description', str(c))}"
            )

        return contradictions

    def _collect_uncertainties(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> List[str]:
        """Collect unresolved uncertainties from all perspectives."""
        uncertainties = []
        for p in perspectives:
            for u in p.uncertainties:
                label = f"[{p.gear.upper()}] {u}"
                if label not in uncertainties:
                    uncertainties.append(label)
        return uncertainties

    def _synthesize_scope(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> str:
        """Synthesize scope implications."""
        impacts = [p.scope_impact for p in perspectives if p.scope_impact]
        if any("expand" in i.lower() for i in impacts):
            return (
                "Scope expansion indicated by one or more gears. "
                "Requires Program Manager approval before proceeding. "
                "No automatic scope expansion permitted."
            )
        return (
            "Scope remains within current mission boundaries. "
            "No scope expansion required for initial phase."
        )

    def _synthesize_authorization(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> str:
        """Synthesize authorization implications."""
        security = next((p for p in perspectives if p.gear == "security"), None)
        if security:
            return (
                f"Authorization assessment: {security.authorization_impact}. "
                f"Security authorization restrictions remain binding. "
                f"No external security work without explicit authorization."
            )
        return "Authorization assessment: PENDING — no security perspective available."

    def _identify_safe_options(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> List[str]:
        """Identify safe next-phase options."""
        safe = []

        scraping = next((p for p in perspectives if p.gear == "scraping"), None)
        if scraping:
            safe.append(
                "Passive schema mapping — enumerate available API fields without active probing"
            )
            safe.append(
                "Pagination analysis — assess API response structure without exceeding rate limits"
            )

        mining = next((p for p in perspectives if p.gear == "mining"), None)
        if mining:
            safe.append(
                "Data quality assessment — evaluate sample data for completeness and consistency"
            )

        evidence_p = next((p for p in perspectives if p.gear == "evidence"), None)
        if evidence_p:
            safe.append(
                "Evidence collection — gather additional samples to improve confidence"
            )

        return safe

    def _identify_blocked_options(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> List[str]:
        """Identify options that are blocked."""
        blocked = []

        blocked.append(
            "External security testing — REQUIRES separate authorization"
        )
        blocked.append(
            "Scope expansion — requires Program Manager approval"
        )
        blocked.append(
            "Production impact testing — prohibited without explicit authorization"
        )
        blocked.append(
            "Unilateral security disposition — all 4 gears must contribute"
        )

        return blocked

    def _recommend_next_phase(
        self,
        perspectives: List[DiscoveryPerspective],
    ) -> List[str]:
        """Recommend next-phase options based on synthesis."""
        recommendations = []

        # Check if this looks like structured catalog
        is_catalog = any(
            "catalog" in p.interpretation.lower() or
            "structured" in p.interpretation.lower()
            for p in perspectives
        )

        if is_catalog:
            recommendations.append(
                "STRUCTURED_CATALOG_INTELLIGENCE_QUALIFICATION: "
                "Qualify the catalog as an intelligence source — "
                "map schema, assess data quality, evaluate commercial value"
            )

        recommendations.append(
            "CONSUME_IN_CURRENT_MISSION: "
            "Use discovery findings to enrich current mission intelligence"
        )

        recommendations.append(
            "SCHEDULE_RECURRING_ACQUISITION: "
            "If high materiality confirmed, schedule regular data acquisition"
        )

        return recommendations

    def get_synthesis(self, discovery_id: str) -> Optional[SynthesisResult]:
        return self._syntheses.get(discovery_id)
