"""
HERMES-PARALLEL-DISCOVERY-001 — Perspective Completion Gate
Requires manager-approved perspectives from all required gears
before any discovery disposition or next-phase decision.

Per Section 8 of the mission spec.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .discovery_types import (
    DiscoveryPerspective, PerspectiveStatus, GateResult,
    DiscoveryRecord,
)
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class DiscoveryPerspectiveGate:
    """Gate requiring manager-approved perspectives from all required gears.
    
    Required gears: SCRAPING, MINING, SECURITY, EVIDENCE
    
    The gate also verifies:
    - Every required gear acknowledged the discovery
    - Every perspective links to evidence
    - Every perspective has manager approval
    - No critical contradiction is unregistered
    - Authorization assessment exists
    """
    
    REQUIRED_GEARS = {"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
    
    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._gate_results: Dict[str, List[GateResult]] = {}  # discovery_id -> [results]
    
    def evaluate(
        self,
        discovery_id: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
        perspectives: List[DiscoveryPerspective],
        acknowledgments_gears: Optional[Set[str]] = None,
        contradictions_registered: Optional[List[dict]] = None,
    ) -> GateResult:
        """Evaluate whether all required perspectives are present and approved.
        
        Args:
            discovery_id: The discovery being evaluated
            mission_id: Mission context
            correlation_id: Correlation for events
            causation_id: Causation for events
            perspectives: The latest perspectives from all gears
            acknowledgments_gears: Which gears have acknowledged (optional)
            contradictions_registered: Registered contradictions (optional)
            
        Returns:
            GateResult with pass/fail status and details
        """
        failures = []
        
        # 1. Check all required gears have perspectives
        perspective_gears = {p.gear.upper() for p in perspectives}
        approved_gears = {
            p.gear.upper() for p in perspectives
            if p.status == PerspectiveStatus.MANAGER_APPROVED.value
        }
        
        missing_gears = self.REQUIRED_GEARS - perspective_gears
        if missing_gears:
            failures.append(
                f"Missing perspectives from: {', '.join(sorted(missing_gears))}"
            )
        
        # 2. Check all perspectives have manager approval
        unapproved = self.REQUIRED_GEARS - approved_gears
        if unapproved:
            failures.append(
                f"Perspectives not manager-approved: {', '.join(sorted(unapproved))}"
            )
        
        # 3. Check every perspective links to evidence
        for p in perspectives:
            if not p.evidence_ids:
                failures.append(
                    f"{p.gear.upper()} perspective has no evidence references"
                )
        
        # 4. Check acknowledgments
        if acknowledgments_gears is not None:
            missing_acks = self.REQUIRED_GEARS - acknowledgments_gears
            if missing_acks:
                failures.append(
                    f"Gears not acknowledged: {', '.join(sorted(missing_acks))}"
                )
        
        # 5. Check for unregistered contradictions
        if contradictions_registered is not None:
            critical_contradictions = [
                c for c in contradictions_registered
                if c.get("severity") == "critical"
            ]
            if critical_contradictions:
                failures.append(
                    f"{len(critical_contradictions)} critical contradiction(s) not resolved"
                )
        
        # 6. Authorization assessment must exist (security perspective)
        sec_perspectives = [
            p for p in perspectives if p.gear == "security"
        ]
        if sec_perspectives:
            sec = sec_perspectives[0]
            if not sec.authorization_impact:
                failures.append("Security perspective lacks authorization assessment")
        
        passed = len(failures) == 0
        
        result = GateResult(
            gate_name="DISCOVERY_PERSPECTIVE_COMPLETION",
            passed=passed,
            missing=sorted(missing_gears) if not passed else [],
            failures=failures,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
        
        # Emit gate event
        event_type = (
            DiscoveryEventType.DISCOVERY_PERSPECTIVE_GATE_PASSED
            if passed else DiscoveryEventType.DISCOVERY_PERSPECTIVE_GATE_FAILED
        )
        
        self._event_bus.publish(DiscoveryEvent.create(
            event_type=event_type,
            discovery_id=discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer="PERSPECTIVE_GATE",
            receiver="ALL",
            gear="",
            manager="",
            evidence_reference="",
            data=result.to_dict(),
        ))
        
        # Store result
        if discovery_id not in self._gate_results:
            self._gate_results[discovery_id] = []
        self._gate_results[discovery_id].append(result)
        
        return result
    
    def get_results(self, discovery_id: str) -> List[GateResult]:
        """Get all gate evaluation results for a discovery."""
        return self._gate_results.get(discovery_id, [])
    
    def get_latest_result(self, discovery_id: str) -> Optional[GateResult]:
        """Get the most recent gate result."""
        results = self._gate_results.get(discovery_id, [])
        return results[-1] if results else None
