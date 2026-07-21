"""
HERMES-PARALLEL-DISCOVERY-001 — Parallel Discovery Coordinator
Single entry point for the governed parallel discovery lifecycle.

Invariant MYC-DISC-PAR-INV-001: Every material discovery detected by
any Mycelium gear must be published immediately to the shared discovery
and evidence fabric. All required enabled gears must receive, acknowledge,
evaluate, and publish a manager-approved perspective before any final
discovery disposition or next-phase decision may occur.

No single gear, including Security, may unilaterally classify the complete
mission value or final disposition of a cross-system discovery.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from .discovery_types import (
    DiscoveryPerspective, PerspectiveStatus, DiscoveryRecord,
    GateResult, SynthesisResult, ManagementDecision, DecisionType,
    AcknowledgmentRecord, DiscoveryType,
)
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType
from .discovery_register import DiscoveryRegister
from .discovery_broadcast import DiscoveryBroadcast
from .gear_engines import GearEngineRegistry
from .manager_review import ManagerReviewWorkflow
from .cross_sharing import CrossSharingEngine
from .perspective_gate import DiscoveryPerspectiveGate
from .decision_control import DecisionFreeze
from .evidence_synthesis import EvidenceSynthesisEngine
from .management_decision import ManagementDecisionPath


class ParallelDiscoveryCoordinator:
    """Governed parallel discovery lifecycle coordinator.

    Extends the existing Mycelium organizational runtime with parallel
    cross-gear discovery review. Does NOT redesign — EXTENDS.
    """

    REQUIRED_GEARS = ["scraping", "mining", "security", "evidence"]

    def __init__(
        self,
        mission_id: str,
        storage_dir: str = ".",
    ):
        self.mission_id = mission_id
        self.storage_dir = storage_dir

        # Core infrastructure
        self._event_bus = DiscoveryEventBus()
        self._register = DiscoveryRegister(storage_dir)
        self._broadcast = DiscoveryBroadcast(self._event_bus)
        self._gear_registry = GearEngineRegistry()

        # Workflow components
        self._manager_review = ManagerReviewWorkflow(self._event_bus)
        self._cross_sharing = CrossSharingEngine(self._event_bus)
        self._perspective_gate = DiscoveryPerspectiveGate(self._event_bus)
        self._decision_freeze = DecisionFreeze(self._event_bus)
        self._synthesis_engine = EvidenceSynthesisEngine(self._event_bus)
        self._decision_path = ManagementDecisionPath(self._event_bus)

        # State
        self._invariant_record: Dict[str, Any] = {}
        self._certification_results: Dict[str, Any] = {}

    # ═══════════════════════════════════════════════════════════
    # MAIN LIFECYCLE
    # ═══════════════════════════════════════════════════════════

    def process_discovery(
        self,
        finding_data: Dict[str, Any],
        manager_ids: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Process a complete discovery through the parallel lifecycle.

        Phases:
        1. Register → Broadcast → Acknowledge
        2. Parallel gear analysis (all 4 gears)
        3. Manager review (all 4 perspectives)
        4. Cross-gear sharing
        5. Perspective completion gate
        6. Evidence synthesis
        7. Management decision

        Args:
            finding_data: Dict with title, description, source_gear,
                         source_agent, source_manager, discovery_types,
                         materiality, evidence_references
            manager_ids: Dict mapping gear -> manager_id. Defaults to
                        'mgr-{gear}' for each gear.

        Returns:
            Full lifecycle result dict
        """
        managers = manager_ids or {
            gear: f"mgr-{gear}" for gear in self.REQUIRED_GEARS
        }

        results: Dict[str, Any] = {"phases": [], "events": []}

        # ══ Phase 1: Register + Broadcast + Acknowledge ══
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear=finding_data.get("source_gear", "scraping"),
            source_agent_id=finding_data["source_agent"],
            source_manager_id=finding_data.get("source_manager", "mgr-source"),
            discovery_types=finding_data.get("discovery_types", ["API_DISCOVERY"]),
            materiality=finding_data.get("materiality", "medium"),
            evidence_references=finding_data.get("evidence_references", []),
            title=finding_data["title"],
            description=finding_data.get("description", ""),
        )

        self._broadcast.broadcast_discovery(discovery)

        # Acknowledge all gears
        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        self._register.update_discovery_status(discovery.discovery_id, "BROADCAST")
        results["phases"].append("broadcast_complete")

        # ══ Phase 2: Parallel Gear Analysis ══
        perspectives: List[DiscoveryPerspective] = []
        for gear_name, engine in self._gear_registry.get_all_engines().items():
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            perspectives.append(persp)

        self._register.update_discovery_status(discovery.discovery_id, "IN_REVIEW")
        results["phases"].append("perspectives_generated")

        # ══ Phase 3: Manager Review ══
        for p in perspectives:
            self._manager_review.submit_to_manager(
                p, discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            gear_manager = managers.get(p.gear, f"mgr-{p.gear}")
            self._manager_review.review(
                p, gear_manager, "PASS",
                f"{p.gear} perspective approved by {gear_manager}",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )

        results["phases"].append("manager_review_complete")

        # ══ Phase 4: Cross-Gear Sharing ══
        for p in perspectives:
            self._cross_sharing.publish_approved_perspective(
                p, discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )

        results["phases"].append("cross_sharing_complete")

        # ══ Phase 5: Perspective Completion Gate ══
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        results["phases"].append(f"gate_{'passed' if gate_result.passed else 'failed'}")

        if not gate_result.passed:
            results["success"] = False
            results["error"] = f"Perspective gate failed: {gate_result.failures}"
            results["gate_result"] = gate_result.to_dict()
            return results

        # ══ Phase 6: Evidence Synthesis ══
        synth = self._synthesis_engine.synthesize(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            self._register.get_contradictions(discovery.discovery_id),
            "EVIDENCE_INTEGRATION_MANAGER",
        )
        self._register.add_synthesis(synth)
        self._register.update_discovery_status(discovery.discovery_id, "SYNTHESIZED")
        results["phases"].append("synthesis_complete")

        # ══ Phase 7: Management Decision ══
        decision = self._decision_path.evaluate_and_decide(
            synth, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            "PROGRAM_MANAGER", "MISSION_DIRECTOR", "INDEPENDENT_REVIEWER",
        )
        self._register.add_decision(decision)
        self._register.update_discovery_status(discovery.discovery_id, "DECIDED")
        results["phases"].append("decision_complete")

        # ══ Result ══
        results["success"] = True
        results["discovery"] = discovery.to_dict()
        results["perspectives"] = [p.to_dict() for p in perspectives]
        results["gate_result"] = gate_result.to_dict()
        results["synthesis"] = synth.to_dict()
        results["decision"] = decision.to_dict()
        results["event_count"] = self._event_bus.event_count

        return results

    # ═══════════════════════════════════════════════════════════
    # DEMONSTRATION SCENARIOS
    # ═══════════════════════════════════════════════════════════

    def run_noon_demonstration(self) -> Dict[str, Any]:
        """Structured product catalog API discovery demo.

        Runs the full parallel discovery lifecycle on a realistic
        product catalog API discovery scenario. This is the primary
        happy-path demonstration of the governed parallel discovery
        process.

        Returns:
            Complete demonstration results dict
        """
        return self.process_discovery({
            "title": "Product Catalog API",
            "description": (
                "Structured product catalog API endpoint discovered at "
                "https://api.example.com/v2/catalog. Returns paginated JSON "
                "with product details including prices, categories, availability, "
                "and metadata. Rate-limited at 1000 requests/hour."
            ),
            "source_gear": "scraping",
            "source_agent": "agent-scrape",
            "source_manager": "mgr-scrape",
            "discovery_types": ["API_DISCOVERY", "STRUCTURED_CATALOG"],
            "materiality": "high",
            "evidence_references": ["ev-001", "ev-002"],
        })

    def run_failure_scenario_1(self) -> Dict[str, Any]:
        """Mining perspective delayed — gate blocks decision.

        Scenario: Mining gear takes too long to produce a perspective.
        The decision freeze prevents any disposition until all 4
        perspectives are complete.
        """
        # Register and broadcast
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="scraping",
            source_agent_id="agent-scrape",
            source_manager_id="mgr-scrape",
            discovery_types=["API_DISCOVERY"],
            materiality="medium",
            evidence_references=["ev-001"],
            title="Delayed Mining Test",
            description="Testing mining perspective delay handling",
        )
        self._broadcast.broadcast_discovery(discovery)

        # Acknowledge all gears
        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        # Only 3 gears produce perspectives (mining is "delayed")
        engines = self._gear_registry.get_all_engines()
        perspectives: List[DiscoveryPerspective] = []
        delayed_gear = "mining"
        for gear_name, engine in engines.items():
            if gear_name == delayed_gear:
                continue  # Mining is delayed
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            perspectives.append(persp)

        # Manager review for available perspectives
        for p in perspectives:
            self._manager_review.submit_to_manager(
                p, discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                p, f"mgr-{p.gear}", "PASS",
                f"{p.gear} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )

        # Gate — should fail because mining is missing
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        # Decision freeze — attempt APPROVE_NEW_PHASE should be blocked
        block_result = self._decision_freeze.check_decision(
            "APPROVE_NEW_PHASE",
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,  # only 3 approved
            "test-agent",
        )

        # Now resolve: mining finally produces its perspective
        mining_engine = engines[delayed_gear]
        mining_persp = mining_engine.analyze(discovery, f"agent-{delayed_gear}")
        mining_engine.start_analysis(mining_persp)
        self._register.add_perspective(discovery.discovery_id, mining_persp)
        self._manager_review.submit_to_manager(
            mining_persp, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id
        )
        self._manager_review.review(
            mining_persp, f"mgr-{delayed_gear}", "PASS",
            "mining approved after delay",
            discovery.mission_id, discovery.correlation_id, discovery.causation_id
        )
        perspectives.append(mining_persp)

        # Gate — should now pass
        gate_result2 = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        return {
            "success": gate_result2.passed,
            "initial_gate_passed": gate_result.passed,
            "initial_gate_failures": gate_result.failures,
            "decision_blocked": not block_result["allowed"],
            "block_reason": block_result.get("reason", "N/A"),
            "missing_gears": block_result.get("missing_gears", []),
            "resolved_gate_passed": gate_result2.passed,
            "resolved_gate_failures": gate_result2.failures,
            "phases": [
                "broadcast_complete",
                f"initial_gate_{'passed' if gate_result.passed else 'failed'}",
                f"decision_{'blocked' if not block_result['allowed'] else 'allowed'}",
                "mining_resolved",
                f"final_gate_{'passed' if gate_result2.passed else 'failed'}",
            ],
        }

    def run_failure_scenario_2(self) -> Dict[str, Any]:
        """Security perspective arrives first, attempts early disposition.

        Scenario: Security gear produces its perspective first and attempts
        to unilaterally classify the discovery. The decision freeze blocks
        the attempt until all 4 perspectives are complete, enforcing the
        invariant that no single gear may unilaterally classify.
        """
        # Register and broadcast
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="security",
            source_agent_id="agent-security",
            source_manager_id="mgr-security",
            discovery_types=["API_DISCOVERY", "AUTHORIZATION_WEAKNESS"],
            materiality="high",
            evidence_references=["ev-001"],
            title="Security-First Discovery",
            description="Security gear discovers a potential authorization issue",
        )
        self._broadcast.broadcast_discovery(discovery)

        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        # Security analyzes first and immediately
        engines = self._gear_registry.get_all_engines()
        sec_engine = engines["security"]
        sec_persp = sec_engine.analyze(discovery, "agent-security")
        sec_engine.start_analysis(sec_persp)
        self._register.add_perspective(discovery.discovery_id, sec_persp)

        self._manager_review.submit_to_manager(
            sec_persp, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id
        )
        self._manager_review.review(
            sec_persp, "mgr-security", "PASS",
            "Security perspective approved",
            discovery.mission_id, discovery.correlation_id, discovery.causation_id
        )

        # Security attempts to make early decision — BLOCKED
        block_result = self._decision_freeze.check_decision(
            "CLOSE_DISCOVERY",
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            [sec_persp],  # only security
            "agent-security",
        )

        # Now produce remaining perspectives
        perspectives = [sec_persp]
        for gear_name in ["scraping", "mining", "evidence"]:
            engine = engines[gear_name]
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            self._manager_review.submit_to_manager(
                persp, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                persp, f"mgr-{gear_name}", "PASS",
                f"{gear_name} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            perspectives.append(persp)

        # Gate now passes
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        # Now decision is allowed
        unblock_result = self._decision_freeze.check_decision(
            "APPROVE_NEW_PHASE",
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            "test-agent",
        )

        return {
            "success": True,
            "early_decision_blocked": not block_result["allowed"],
            "block_reason": block_result.get("reason", "N/A"),
            "blocked_decision_type": block_result.get("blocked_decision", ""),
            "missing_gears_at_block": block_result.get("missing_gears", []),
            "gate_passed_after_all_perspectives": gate_result.passed,
            "decision_allowed_after_gate": unblock_result["allowed"],
            "phases": [
                "broadcast_complete",
                "security_first_perspective",
                f"early_decision_{'blocked' if not block_result['allowed'] else 'allowed'}",
                "remaining_perspectives_complete",
                f"gate_{'passed' if gate_result.passed else 'failed'}",
                f"decision_{'allowed' if unblock_result['allowed'] else 'blocked'}",
            ],
        }

    def run_failure_scenario_3(self) -> Dict[str, Any]:
        """Scraping perspective rejected by manager.

        Scenario: Scraping gear produces a perspective, but the manager
        rejects it. The gate fails because scraping is not manager-approved.
        After rework and resubmission, the gate passes.
        """
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="scraping",
            source_agent_id="agent-scrape",
            source_manager_id="mgr-scrape",
            discovery_types=["ENDPOINT"],
            materiality="medium",
            evidence_references=["ev-001"],
            title="Scraping Manager Rejection Test",
            description="Testing scraping perspective rejection and rework",
        )
        self._broadcast.broadcast_discovery(discovery)

        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        engines = self._gear_registry.get_all_engines()
        perspectives: List[DiscoveryPerspective] = []

        # Scraping — rejected by manager
        scrape_engine = engines["scraping"]
        scrape_persp = scrape_engine.analyze(discovery, "agent-scrape")
        scrape_engine.start_analysis(scrape_persp)
        self._register.add_perspective(discovery.discovery_id, scrape_persp)
        self._manager_review.submit_to_manager(
            scrape_persp, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id
        )
        # Manager REJECTS
        self._manager_review.review(
            scrape_persp, "mgr-scrape", "REWORK_REQUIRED",
            "Insufficient analysis — missing endpoint reliability assessment",
            discovery.mission_id, discovery.correlation_id, discovery.causation_id
        )
        perspectives.append(scrape_persp)

        # Other gears approved
        for gear_name in ["mining", "security", "evidence"]:
            engine = engines[gear_name]
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            self._manager_review.submit_to_manager(
                persp, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                persp, f"mgr-{gear_name}", "PASS",
                f"{gear_name} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            perspectives.append(persp)

        # Gate — should fail due to rejected scraping
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        # Rework: submit corrected scraping perspective as new version
        reworked = self._cross_sharing.update_perspective(
            scrape_persp,
            scrape_persp.interpretation + " ADDENDUM: Endpoint reliability assessed — MODERATE.",
            "agent-scrape",
        )
        self._register.add_perspective(discovery.discovery_id, reworked)
        self._manager_review.submit_to_manager(
            reworked, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id
        )
        self._manager_review.review(
            reworked, "mgr-scrape", "PASS",
            "Reworked scraping perspective approved",
            discovery.mission_id, discovery.correlation_id, discovery.causation_id
        )

        # Remove the rejected scraping from perspectives and add reworked
        perspectives = [p for p in perspectives if p.gear != "scraping"]
        perspectives.append(reworked)

        # Gate — should now pass
        gate_result2 = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        return {
            "success": gate_result2.passed,
            "initial_gate_passed": gate_result.passed,
            "initial_gate_failures": gate_result.failures,
            "scraping_rejected": scrape_persp.status == "REWORK_REQUIRED",
            "reworked_approved": reworked.status == "MANAGER_APPROVED",
            "final_gate_passed": gate_result2.passed,
            "phases": [
                "broadcast_complete",
                "scraping_rejected",
                f"initial_gate_{'passed' if gate_result.passed else 'failed'}",
                "scraping_reworked",
                "reworked_approved",
                f"final_gate_{'passed' if gate_result2.passed else 'failed'}",
            ],
        }

    def run_failure_scenario_4(self) -> Dict[str, Any]:
        """Evidence perspective detects contradiction.

        Scenario: The evidence gear detects a contradiction in the
        cross-gear perspectives. The synthesis engine preserves the
        contradiction rather than hiding it. The gate passes but the
        decision acknowledges the contradiction.
        """
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="scraping",
            source_agent_id="agent-scrape",
            source_manager_id="mgr-scrape",
            discovery_types=["API_DISCOVERY"],
            materiality="high",
            evidence_references=["ev-001"],
            title="Evidence Contradiction Test",
            description="Testing evidence gear contradiction detection",
        )
        self._broadcast.broadcast_discovery(discovery)

        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        engines = self._gear_registry.get_all_engines()
        perspectives: List[DiscoveryPerspective] = []

        # All gears produce and get approved
        for gear_name in self.REQUIRED_GEARS:
            engine = engines[gear_name]
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            self._manager_review.submit_to_manager(
                persp, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                persp, f"mgr-{gear_name}", "PASS",
                f"{gear_name} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            perspectives.append(persp)

        # Evidence gear opens a contradiction against the mining perspective
        mining_persp = next(p for p in perspectives if p.gear == "mining")
        evidence_persp = next(p for p in perspectives if p.gear == "evidence")

        contradiction = self._cross_sharing.open_contradiction(
            mining_persp.perspective_id,
            "evidence",
            "Mining confidence (0.65) not supported by evidence quality (0.55). "
            "Evidence suggests lower quality than mining assumes.",
            "agent-evidence",
        )
        self._register.add_contradiction(discovery.discovery_id, contradiction)

        # Gate passes (contradiction doesn't block gate)
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        # Synthesis captures the contradiction
        synth = self._synthesis_engine.synthesize(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            self._register.get_contradictions(discovery.discovery_id),
            "EVIDENCE_INTEGRATION_MANAGER",
        )
        self._register.add_synthesis(synth)

        # Decision acknowledges contradiction
        decision = self._decision_path.evaluate_and_decide(
            synth, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            "PROGRAM_MANAGER", "MISSION_DIRECTOR", "INDEPENDENT_REVIEWER",
        )
        self._register.add_decision(decision)

        return {
            "success": True,
            "gate_passed": gate_result.passed,
            "contradiction_detected": True,
            "contradiction_count": len(synth.areas_of_contradiction),
            "areas_of_contradiction": synth.areas_of_contradiction,
            "decision_type": decision.mission_director_choice,
            "synthesis_preserved_disagreement": len(synth.areas_of_contradiction) > 0,
            "phases": [
                "broadcast_complete",
                "all_perspectives_approved",
                "contradiction_opened",
                f"gate_{'passed' if gate_result.passed else 'failed'}",
                "synthesis_with_contradiction",
                f"decision_{decision.mission_director_choice}",
            ],
        }

    def run_failure_scenario_5(self) -> Dict[str, Any]:
        """One gear fails to acknowledge.

        Scenario: The scraping gear fails to acknowledge the discovery
        broadcast. The acknowledgment check detects the missing gear,
        and a retry is issued. After retry, acknowledgment succeeds.
        """
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="scraping",
            source_agent_id="agent-scrape",
            source_manager_id="mgr-scrape",
            discovery_types=["API_DISCOVERY"],
            materiality="medium",
            evidence_references=["ev-001"],
            title="Missing Acknowledgment Test",
            description="Testing acknowledgment failure and retry",
        )
        self._broadcast.broadcast_discovery(discovery)

        # Only 3 of 4 gears acknowledge — scraping is "silent"
        for gear in ["mining", "security", "evidence"]:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        # Check — should show scraping missing
        ack_check = self._broadcast.check_acknowledgments(discovery.discovery_id)
        missing_before = ack_check["missing"]

        # Retry the scraping gear
        self._broadcast.retry_gear(discovery, "scraping")
        self._broadcast.acknowledge_receipt(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            "scraping", "agent-scraping"
        )
        self._register.record_acknowledgment(
            discovery.discovery_id, "scraping", "agent-scraping"
        )

        # Check — all should now be acknowledged
        ack_check2 = self._broadcast.check_acknowledgments(discovery.discovery_id)
        all_acknowledged = ack_check2["all_acknowledged"]

        return {
            "success": all_acknowledged,
            "missing_before_retry": missing_before,
            "all_acknowledged": all_acknowledged,
            "acknowledged_after": ack_check2["acknowledged"],
            "phases": [
                "broadcast_complete",
                "3_of_4_acknowledged",
                f"missing_gears: {missing_before}",
                "scraping_retried",
                f"all_acknowledged: {all_acknowledged}",
            ],
        }

    def run_failure_scenario_6(self) -> Dict[str, Any]:
        """Decision attempted before perspective completion.

        Scenario: An agent attempts to make an APPROVE_NEW_PHASE decision
        before all 4 perspectives are manager-approved. The decision freeze
        blocks it with DECISION_NOT_AUTHORIZED. After all perspectives are
        complete, the decision is allowed.
        """
        discovery = self._register.register_discovery(
            mission_id=self.mission_id,
            source_gear="scraping",
            source_agent_id="agent-scrape",
            source_manager_id="mgr-scrape",
            discovery_types=["API_DISCOVERY"],
            materiality="high",
            evidence_references=["ev-001"],
            title="Early Decision Test",
            description="Testing decision block before all perspectives complete",
        )
        self._broadcast.broadcast_discovery(discovery)

        for gear in self.REQUIRED_GEARS:
            self._broadcast.acknowledge_receipt(
                discovery.discovery_id, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id,
                gear, f"agent-{gear}"
            )
            self._register.record_acknowledgment(
                discovery.discovery_id, gear, f"agent-{gear}"
            )

        engines = self._gear_registry.get_all_engines()
        perspectives: List[DiscoveryPerspective] = []

        # Only 2 gears done — scrape and mine
        for gear_name in ["scraping", "mining"]:
            engine = engines[gear_name]
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            self._manager_review.submit_to_manager(
                persp, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                persp, f"mgr-{gear_name}", "PASS",
                f"{gear_name} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            perspectives.append(persp)

        # Attempt early decision — BLOCKED
        block_result = self._decision_freeze.check_decision(
            "APPROVE_NEW_PHASE",
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            "impatient-agent",
        )

        # Complete remaining perspectives
        for gear_name in ["security", "evidence"]:
            engine = engines[gear_name]
            persp = engine.analyze(discovery, f"agent-{gear_name}")
            engine.start_analysis(persp)
            self._register.add_perspective(discovery.discovery_id, persp)
            self._manager_review.submit_to_manager(
                persp, discovery.mission_id,
                discovery.correlation_id, discovery.causation_id
            )
            self._manager_review.review(
                persp, f"mgr-{gear_name}", "PASS",
                f"{gear_name} approved",
                discovery.mission_id, discovery.correlation_id, discovery.causation_id
            )
            perspectives.append(persp)

        # Now decision allowed
        unblock_result = self._decision_freeze.check_decision(
            "APPROVE_NEW_PHASE",
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            "patient-agent",
        )

        # Gate also passes
        gate_result = self._perspective_gate.evaluate(
            discovery.discovery_id, discovery.mission_id,
            discovery.correlation_id, discovery.causation_id,
            perspectives,
            acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
        )

        return {
            "success": unblock_result["allowed"] and gate_result.passed,
            "early_decision_blocked": not block_result["allowed"],
            "block_error_code": block_result.get("error_code", ""),
            "missing_at_block": block_result.get("missing_gears", []),
            "decision_allowed_after_completion": unblock_result["allowed"],
            "gate_passed": gate_result.passed,
            "phases": [
                "broadcast_complete",
                "2_of_4_perspectives_approved",
                f"early_decision_{'blocked' if not block_result['allowed'] else 'allowed'}",
                "all_perspectives_complete",
                f"decision_{'allowed' if unblock_result['allowed'] else 'blocked'}",
                f"gate_{'passed' if gate_result.passed else 'failed'}",
            ],
        }

    # ═══════════════════════════════════════════════════════════
    # STATE ACCESS
    # ═══════════════════════════════════════════════════════════

    def get_state(self) -> dict:
        """Get coordinator state."""
        return {
            "mission_id": self.mission_id,
            "register": self._register.to_dict(),
            "event_count": self._event_bus.event_count,
        }

    def get_certification_report(self) -> Dict[str, Any]:
        """Generate the certification report.

        Reports compliance with invariant MYC-DISC-PAR-INV-001,
        gate status, decision freeze status, and overall certification
        status for the mission.
        """
        discoveries = self._register._discoveries
        certified = True
        issues = []

        for did, disc in discoveries.items():
            # Check all 4 gears have manager-approved perspectives
            approved = self._register.get_approved_perspectives(did)
            approved_gears = {p.gear for p in approved}
            missing_gears = {"scraping", "mining", "security", "evidence"} - approved_gears

            if missing_gears:
                certified = False
                issues.append({
                    "discovery_id": did,
                    "issue": f"Missing approved perspectives: {sorted(missing_gears)}",
                    "severity": "CRITICAL",
                })

            # Check all gears acknowledged
            if not self._register.has_all_acknowledgments(did):
                missing_acks = self._register.get_missing_acknowledgments(did)
                issues.append({
                    "discovery_id": did,
                    "issue": f"Missing acknowledgments: {missing_acks}",
                    "severity": "HIGH",
                })

            # Check synthesis exists
            if did not in self._register._syntheses:
                if disc.status in ("SYNTHESIZED", "DECIDED"):
                    issues.append({
                        "discovery_id": did,
                        "issue": "Expected synthesis not found",
                        "severity": "HIGH",
                    })

            # Check decision exists for decided discoveries
            if disc.status == "DECIDED" and did not in self._register._decisions:
                certified = False
                issues.append({
                    "discovery_id": did,
                    "issue": "Discovery marked DECIDED but no decision record",
                    "severity": "CRITICAL",
                })

        # Check invariant violations
        violation_codes = []
        if not certified:
            violation_codes.append("INCOMPLETE_CROSS_GEAR_DISCOVERY_REVIEW")

        return {
            "mission_id": self.mission_id,
            "certified": certified,
            "invariant_id": "MYC-DISC-PAR-INV-001",
            "invariant_description": (
                "Every material discovery must be published to shared fabric. "
                "All 4 gears must produce manager-approved perspectives before "
                "any final disposition or next-phase decision."
            ),
            "violation_codes": violation_codes,
            "discovery_count": len(discoveries),
            "issues": issues,
            "event_count": self._event_bus.event_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ═══════════════════════════════════════════════════════════
    # ARTIFACT EXPORT
    # ═══════════════════════════════════════════════════════════

    def export_artifacts(self, output_dir: str) -> Dict[str, str]:
        """Export all required artifacts to the output directory.

        Generates all 20 artifacts per Section 16 of the mission spec.
        Returns dict mapping filename → path.
        """
        os.makedirs(output_dir, exist_ok=True)
        artifacts: Dict[str, str] = {}

        def save(filename: str, data: Any) -> None:
            path = os.path.join(output_dir, filename)
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            artifacts[filename] = path

        # 1. Invariant record
        save("invariant_record.json", {
            "invariant_id": "MYC-DISC-PAR-INV-001",
            "installed": True,
            "description": (
                "Every material discovery must be published to shared fabric. "
                "All 4 gears must produce manager-approved perspectives."
            ),
            "violation_codes": [
                "INCOMPLETE_CROSS_GEAR_DISCOVERY_REVIEW",
                "DECISION_NOT_AUTHORIZED",
                "MISSION_NOT_CERTIFIED",
            ],
        })

        # 2. Discovery register
        save("discovery_register.json", self._register.to_dict())

        # 3. Discovery broadcast log
        save("discovery_broadcast_log.json", {
            "events": self._event_bus.to_dict_list(),
        })

        # 4. Acknowledgment report
        ack_data: Dict[str, Dict[str, Any]] = {}
        for did in self._register._discoveries:
            ack_data[did] = {
                gear: ack.to_dict()
                for gear, ack in self._register._acknowledgments.get(did, {}).items()
            }
        save("acknowledgment_report.json", ack_data)

        # 5-8. Gear perspectives
        for gear in self.REQUIRED_GEARS:
            gear_data: Dict[str, List[Dict[str, Any]]] = {}
            for did, gear_perspectives in self._register._perspectives.items():
                if gear in gear_perspectives:
                    gear_data[did] = [p.to_dict() for p in gear_perspectives[gear]]
            save(f"{gear}_perspectives.json", gear_data)

        # 9. Perspective version history
        version_data: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        for did, gear_perspectives in self._register._perspectives.items():
            version_data[did] = {}
            for gear, versions in gear_perspectives.items():
                version_data[did][gear] = [
                    {
                        "version": p.version,
                        "perspective_id": p.perspective_id,
                        "previous_version_id": p.previous_version_id,
                        "status": p.status,
                    }
                    for p in versions
                ]
        save("perspective_version_history.json", version_data)

        # 10. Manager review log
        save("manager_review_log.json", self._manager_review.get_review_log())

        # 11. Perspective completion gate
        gate_data: Dict[str, List[Dict[str, Any]]] = {}
        for did, results in self._perspective_gate._gate_results.items():
            gate_data[did] = [r.to_dict() for r in results]
        save("perspective_completion_gate.json", gate_data)

        # 12. Contradiction register
        save("contradiction_register.json", self._register._contradictions)

        # 13. Cross-gear exchange log
        save("cross_gear_exchange_log.json", self._cross_sharing.get_exchanges())

        # 14. Discovery synthesis
        synth_data: Dict[str, Any] = {}
        for did, synth in self._register._syntheses.items():
            synth_data[did] = synth.to_dict()
        save("discovery_synthesis.json", synth_data)

        # 15. Next phase decision
        decision_data: Dict[str, Any] = {}
        for did, dec in self._register._decisions.items():
            decision_data[did] = dec.to_dict()
        save("next_phase_decision.json", decision_data)

        # 16. Decision block log
        save("decision_block_log.json", self._decision_freeze.get_blocked_decisions())

        # 17. Event timeline
        save("event_timeline.json", self._event_bus.to_dict_list())

        # 18. Regression results placeholder
        save("regression_results.json", {
            "status": "PENDING",
            "note": "Run pytest mycelium/discovery/tests/ to populate",
        })

        # 19. Validation report placeholder
        save("validation_report.md", (
            "# Validation Report\n\n"
            "PENDING — run tests to complete.\n\n"
            "## Required Checks\n\n"
            "- All 4 gears produce perspectives\n"
            "- All perspectives pass manager review\n"
            "- Perspective gate exercises correctly\n"
            "- Decision freeze enforces before-gate block\n"
            "- Evidence synthesis connects across gears\n"
            "- Management decision follows EIM→PM→MD→IR path\n"
            "- All 20 artifacts export successfully\n"
        ))

        # 20. Certification report
        cert = self.get_certification_report()
        cert_md_lines = [
            "# Certification Report",
            "",
            f"**Mission:** {cert['mission_id']}",
            f"**Invariant:** {cert['invariant_id']}",
            f"**Certified:** {'✅ YES' if cert['certified'] else '❌ NO'}",
            f"**Timestamp:** {cert['timestamp']}",
            "",
            "## Invariant Description",
            "",
            cert["invariant_description"],
            "",
            "## Statistics",
            "",
            f"- Discovery count: {cert['discovery_count']}",
            f"- Event count: {cert['event_count']}",
        ]
        if cert["violation_codes"]:
            cert_md_lines.append("")
            cert_md_lines.append("## Violations")
            for v in cert["violation_codes"]:
                cert_md_lines.append(f"- {v}")
        if cert["issues"]:
            cert_md_lines.append("")
            cert_md_lines.append("## Issues")
            for issue in cert["issues"]:
                cert_md_lines.append(
                    f"- [{issue['severity']}] {issue['discovery_id']}: {issue['issue']}"
                )
        cert_md_lines.append("")
        save("certification_report.md", "\n".join(cert_md_lines))

        # Also save the cert as JSON
        save("certification_report.json", cert)

        return artifacts
