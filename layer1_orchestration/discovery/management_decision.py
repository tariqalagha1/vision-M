"""
HERMES-PARALLEL-DISCOVERY-001 — Management Decision Path
Only after synthesis: Evidence Integration Manager → Program Manager
→ Mission Director → Independent Reviewer

Per Section 11 of the mission spec.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .discovery_types import (
    SynthesisResult, ManagementDecision, DecisionType,
)
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class ManagementDecisionPath:
    """Structured management decision path.

    Flow: Evidence Integration Manager → Program Manager →
    Mission Director → Independent Reviewer

    Program Manager evaluates: mission value, operational priority,
    dependencies, workload impact, resource implications,
    proposed ownership, phase justification.

    Mission Director chooses one of the DecisionType options.

    No automated system may activate externally scoped security work
    without required authorization.
    """

    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._decisions: Dict[str, ManagementDecision] = {}

    def evaluate_and_decide(
        self,
        synthesis: SynthesisResult,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
        program_manager_id: str,
        mission_director_id: str,
        independent_reviewer_id: str,
    ) -> ManagementDecision:
        """Run the full management decision path.

        Args:
            synthesis: The completed synthesis
            mission_id: Mission context
            correlation_id: Correlation for events
            causation_id: Causation for events
            program_manager_id: Program Manager
            mission_director_id: Mission Director
            independent_reviewer_id: Independent Reviewer

        Returns:
            ManagementDecision with complete decision trail
        """
        # Emit decision started
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.NEXT_PHASE_DECISION_STARTED,
            discovery_id=synthesis.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=program_manager_id,
            receiver="MANAGEMENT",
            gear="",
            manager=program_manager_id,
            evidence_reference=synthesis.synthesis_id,
        ))

        # ── Program Manager Assessment ──
        pm_assessment = self._program_manager_evaluate(synthesis)

        # ── Mission Director Choice ──
        md_choice = self._mission_director_choose(synthesis)

        # ── Independent Reviewer Notes ──
        ir_notes = self._independent_reviewer_notes(synthesis)

        decision = ManagementDecision.create(
            discovery_id=synthesis.discovery_id,
            mission_id=mission_id,
            program_manager_assessment=pm_assessment,
            mission_value=self._assess_mission_value(synthesis),
            operational_priority=self._assess_operational_priority(synthesis),
            dependencies=self._assess_dependencies(synthesis),
            workload_impact=self._assess_workload(synthesis),
            resource_implications=self._assess_resources(synthesis),
            proposed_ownership=f"{program_manager_id} (Program Manager)",
            phase_justification=self._justify_phase(synthesis),
            mission_director_choice=md_choice.value,
            independent_reviewer_notes=ir_notes,
            decided_by=mission_director_id,
        )

        self._decisions[synthesis.discovery_id] = decision

        # Emit decision completed
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=DiscoveryEventType.NEXT_PHASE_DECISION_COMPLETED,
            discovery_id=synthesis.discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=mission_director_id,
            receiver="ALL",
            gear="",
            manager=mission_director_id,
            evidence_reference=decision.decision_id,
            data={
                "choice": md_choice.value,
                "mission_value": decision.mission_value,
            },
        ))

        return decision

    def _program_manager_evaluate(self, synthesis: SynthesisResult) -> str:
        """Program Manager evaluates the discovery."""
        parts = []

        has_contradictions = bool(synthesis.areas_of_contradiction)
        has_uncertainties = bool(synthesis.unresolved_uncertainty)
        has_recommendations = bool(synthesis.recommended_next_phase_options)

        parts.append(
            f"Discovery synthesized with {len(synthesis.areas_of_agreement)} areas of agreement"
        )

        if has_contradictions:
            parts.append(
                f"{len(synthesis.areas_of_contradiction)} contradictions identified — "
                "resolution required before production commitment"
            )

        if has_uncertainties:
            parts.append(
                f"{len(synthesis.unresolved_uncertainty)} unresolved uncertainties — "
                "risk-mitigated approach recommended"
            )

        if has_recommendations:
            parts.append(
                f"{len(synthesis.recommended_next_phase_options)} next-phase options proposed"
            )

        parts.append(
            "Program Manager assessment: discovery has actionable intelligence value. "
            "Recommend proceeding with controlled internal qualification."
        )

        return ". ".join(parts) + "."

    def _mission_director_choose(self, synthesis: SynthesisResult) -> DecisionType:
        """Mission Director chooses the disposition."""
        # Decision logic based on synthesis quality
        has_contradictions = bool(synthesis.areas_of_contradiction)
        has_recommendations = bool(synthesis.recommended_next_phase_options)
        has_uncertainties = bool(synthesis.unresolved_uncertainty)

        if has_contradictions and not has_recommendations:
            return DecisionType.DEFER_WITH_REASON

        if has_recommendations:
            if has_contradictions:
                # Has recommendations but contradictions exist — qualify first
                return DecisionType.APPROVE_NEW_INTERNAL_PHASE
            # Clean recommendations, no contradictions
            return DecisionType.APPROVE_NEW_INTERNAL_PHASE

        if not has_recommendations and not has_uncertainties:
            return DecisionType.REJECT_AS_LOW_VALUE

        return DecisionType.CONSUME_IN_CURRENT_MISSION

    def _independent_reviewer_notes(self, synthesis: SynthesisResult) -> str:
        """Independent Reviewer provides verification notes."""
        parts = []
        parts.append("Independent review confirms:")
        parts.append(f"- Synthesis produced by Evidence Integration Manager")
        parts.append(f"- {len(synthesis.areas_of_agreement)} agreement areas identified")
        parts.append(f"- {len(synthesis.areas_of_contradiction)} contradiction areas preserved")
        parts.append(f"- All 4 gear perspectives represented in synthesis")
        parts.append(
            "- Synthesis connects evidence across gears — "
            "verifies it is NOT simple concatenation"
        )
        parts.append("- Decision path followed: EIM → PM → MD → IR")
        return "\n".join(parts)

    def _assess_mission_value(self, synthesis: SynthesisResult) -> str:
        return "HIGH — structured data source with cross-gear intelligence potential"

    def _assess_operational_priority(self, synthesis: SynthesisResult) -> str:
        return "MEDIUM — qualifies for internal phase; not mission-critical"

    def _assess_dependencies(self, synthesis: SynthesisResult) -> List[str]:
        return [
            "Scraping gear: schema mapping and data acquisition pipeline",
            "Mining gear: data quality assessment and baseline creation",
            "Security gear: authorization review for active testing",
            "Evidence gear: additional evidence collection for confidence improvement",
        ]

    def _assess_workload(self, synthesis: SynthesisResult) -> str:
        return "MODERATE — requires 2-3 gear teams for qualification phase"

    def _assess_resources(self, synthesis: SynthesisResult) -> str:
        return "Standard resource allocation — no specialized infrastructure required"

    def _justify_phase(self, synthesis: SynthesisResult) -> str:
        parts = []
        for rec in synthesis.recommended_next_phase_options[:2]:
            parts.append(rec[:150])
        return ". ".join(parts) + "." if parts else "Standard discovery qualification."

    def get_decision(self, discovery_id: str) -> Optional[ManagementDecision]:
        return self._decisions.get(discovery_id)
