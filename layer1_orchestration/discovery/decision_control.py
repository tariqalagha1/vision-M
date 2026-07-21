"""
HERMES-PARALLEL-DISCOVERY-001 — Decision Freeze
Before all required perspectives are complete, prohibits:
- APPROVE_NEW_PHASE
- ACTIVATE_NEW_PHASE
- DEFER_DISCOVERY
- REJECT_DISCOVERY
- CLOSE_DISCOVERY
- FINALIZE_MISSION

Returns: DECISION_BLOCKED with MISSING_REQUIRED_PERSPECTIVES

Per Section 9 of the mission spec.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid

from .discovery_types import (
    DiscoveryPerspective, PerspectiveStatus, GateResult,
)
from .event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType


class DecisionFreeze:
    """Enforces decision freeze until all required perspectives are complete.
    
    Prohibited decisions before gate passes:
    - APPROVE_NEW_PHASE
    - ACTIVATE_NEW_PHASE
    - DEFER_DISCOVERY
    - REJECT_DISCOVERY
    - CLOSE_DISCOVERY
    - FINALIZE_MISSION
    """
    
    PROHIBITED_DECISIONS = {
        "APPROVE_NEW_PHASE",
        "ACTIVATE_NEW_PHASE",
        "DEFER_DISCOVERY",
        "REJECT_DISCOVERY",
        "CLOSE_DISCOVERY",
        "FINALIZE_MISSION",
    }
    
    REQUIRED_GEARS = {"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
    
    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._blocked_decisions: List[dict] = []
        self._freeze_active: Dict[str, bool] = {}  # discovery_id -> frozen
    
    def check_decision(
        self,
        decision_type: str,
        discovery_id: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
        approved_perspectives: List[DiscoveryPerspective],
        requester: str,
    ) -> Dict[str, Any]:
        """Check whether a decision is allowed.
        
        If the decision is prohibited and the gate has not passed,
        returns DECISION_BLOCKED with missing gears listed.
        
        Returns:
            dict with 'allowed', 'reason', 'missing_gears', 'blocked_decision'
        """
        approved_gears = {
            p.gear.upper() for p in approved_perspectives
            if p.status == PerspectiveStatus.MANAGER_APPROVED.value
        }
        
        missing = self.REQUIRED_GEARS - approved_gears
        gate_passed = len(missing) == 0
        
        # Decision is prohibited type and gate not passed
        if decision_type in self.PROHIBITED_DECISIONS and not gate_passed:
            blocked = {
                "allowed": False,
                "error_code": "DECISION_BLOCKED",
                "reason": f"MISSING_REQUIRED_PERSPECTIVES: {', '.join(sorted(missing))}",
                "blocked_decision": decision_type,
                "missing_gears": sorted(missing),
                "discovery_id": discovery_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            
            self._blocked_decisions.append(blocked)
            
            self._event_bus.publish(DiscoveryEvent.create(
                event_type=DiscoveryEventType.DECISION_ATTEMPT_BLOCKED,
                discovery_id=discovery_id,
                mission_id=mission_id,
                correlation_id=correlation_id,
                causation_id=causation_id,
                producer=requester,
                receiver="DECISION_FREEZE",
                gear="",
                manager="",
                evidence_reference="",
                data={
                    "blocked_decision": decision_type,
                    "missing_gears": sorted(missing),
                },
            ))
            
            return blocked
        
        return {
            "allowed": True,
            "reason": "Gate passed" if gate_passed else "Decision type not prohibited",
            "missing_gears": sorted(missing),
            "discovery_id": discovery_id,
        }
    
    def activate_freeze(self, discovery_id: str) -> None:
        """Activate the decision freeze for a discovery."""
        self._freeze_active[discovery_id] = True
    
    def deactivate_freeze(self, discovery_id: str) -> None:
        """Deactivate the decision freeze (after gate passes)."""
        self._freeze_active[discovery_id] = False
    
    def is_frozen(self, discovery_id: str) -> bool:
        """Check if a discovery is under decision freeze."""
        return self._freeze_active.get(discovery_id, True)
    
    def get_blocked_decisions(self, discovery_id: Optional[str] = None) -> List[dict]:
        """Get blocked decision history."""
        if discovery_id:
            return [d for d in self._blocked_decisions if d.get("discovery_id") == discovery_id]
        return list(self._blocked_decisions)
    
    def can_approve_next_phase(
        self,
        discovery_id: str,
        approved_perspectives: List[DiscoveryPerspective],
    ) -> bool:
        """Shortcut check: can we proceed to next-phase decision?
        
        Returns True only when ALL required gears have manager-approved perspectives.
        """
        approved_gears = {
            p.gear.upper() for p in approved_perspectives
            if p.status == PerspectiveStatus.MANAGER_APPROVED.value
        }
        return self.REQUIRED_GEARS.issubset(approved_gears)
