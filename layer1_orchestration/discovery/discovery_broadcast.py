"""
HERMES-PARALLEL-DISCOVERY-001 — Discovery Broadcast Engine
===========================================================
Broadcasts discoveries to all required gears and tracks acknowledgments.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import uuid

from .discovery_types import (
    DiscoveryRecord, DiscoveryType, AcknowledgmentRecord,
)
from .event_bus import (
    DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType,
)


class DiscoveryBroadcast:
    """Broadcast engine for parallel discovery distribution.

    Publishes DISCOVERY_DETECTED, DISCOVERY_REGISTERED, DISCOVERY_BROADCAST.
    Tracks DISCOVERY_RECEIVED and DISCOVERY_ACKNOWLEDGED from each gear.
    A publication without acknowledgment does not count as cooperation.
    """

    REQUIRED_GEARS = ["scraping", "mining", "security", "evidence"]

    def __init__(self, event_bus: DiscoveryEventBus):
        self._event_bus = event_bus
        self._acknowledgment_callbacks: Dict[str, List[Callable]] = {}  # discovery_id -> [callbacks]
        self._timeout_seconds = 30  # Default acknowledgment timeout

    def broadcast_discovery(
        self,
        discovery: DiscoveryRecord,
        callback: Optional[Callable] = None,
    ) -> None:
        """Broadcast a discovery to all required gears.

        Emits: DISCOVERY_DETECTED → DISCOVERY_REGISTERED → DISCOVERY_BROADCAST

        Args:
            discovery: The registered DiscoveryRecord
            callback: Optional callback for each gear's acknowledgment
        """
        mission = discovery.mission_id
        corr = discovery.correlation_id
        caus = discovery.causation_id
        did = discovery.discovery_id

        # 1. DISCOVERY_DETECTED
        detected_event = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_DETECTED,
            discovery_id=did,
            mission_id=mission,
            correlation_id=corr,
            causation_id=caus,
            producer=discovery.source_gear,
            receiver="ALL",
            gear=discovery.source_gear,
            manager=discovery.source_manager_id,
            evidence_reference=",".join(discovery.evidence_references),
            data={
                "discovery_types": discovery.discovery_types,
                "materiality": discovery.materiality,
            },
        )
        self._event_bus.publish(detected_event)

        # 2. DISCOVERY_REGISTERED
        registered_event = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_REGISTERED,
            discovery_id=did,
            mission_id=mission,
            correlation_id=corr,
            causation_id=caus,
            producer="DISCOVERY_REGISTER",
            receiver="ALL",
            gear=discovery.source_gear,
            manager=discovery.source_manager_id,
            evidence_reference=",".join(discovery.evidence_references),
        )
        self._event_bus.publish(registered_event)

        # 3. DISCOVERY_BROADCAST — one per gear
        for gear in self.REQUIRED_GEARS:
            broadcast_event = DiscoveryEvent.create(
                event_type=DiscoveryEventType.DISCOVERY_BROADCAST,
                discovery_id=did,
                mission_id=mission,
                correlation_id=corr,
                causation_id=caus,
                producer="DISCOVERY_BROADCAST",
                receiver=gear,
                gear=gear,
                manager=discovery.source_manager_id,
                evidence_reference=",".join(discovery.evidence_references),
                data={
                    "discovery_types": discovery.discovery_types,
                    "materiality": discovery.materiality,
                    "source_gear": discovery.source_gear,
                    "source_agent": discovery.source_agent_id,
                },
            )
            self._event_bus.publish(broadcast_event)

        if callback:
            if did not in self._acknowledgment_callbacks:
                self._acknowledgment_callbacks[did] = []
            self._acknowledgment_callbacks[did].append(callback)

    def acknowledge_receipt(
        self,
        discovery_id: str,
        mission_id: str,
        correlation_id: str,
        causation_id: str,
        gear: str,
        agent_id: str,
    ) -> DiscoveryEvent:
        """Record that a gear received and acknowledged the discovery.

        Emits both DISCOVERY_RECEIVED and DISCOVERY_ACKNOWLEDGED.
        """
        # DISCOVERY_RECEIVED
        received = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_RECEIVED,
            discovery_id=discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=gear,
            receiver="DISCOVERY_REGISTER",
            gear=gear,
            manager="",
            evidence_reference="",
            data={"agent_id": agent_id},
        )
        self._event_bus.publish(received)

        # DISCOVERY_ACKNOWLEDGED
        acknowledged = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_ACKNOWLEDGED,
            discovery_id=discovery_id,
            mission_id=mission_id,
            correlation_id=correlation_id,
            causation_id=causation_id,
            producer=gear,
            receiver="DISCOVERY_REGISTER",
            gear=gear,
            manager="",
            evidence_reference="",
            data={"agent_id": agent_id},
        )
        self._event_bus.publish(acknowledged)

        # Notify callbacks
        if discovery_id in self._acknowledgment_callbacks:
            for cb in self._acknowledgment_callbacks[discovery_id]:
                cb(gear, agent_id)

        return acknowledged

    def check_acknowledgments(
        self,
        discovery_id: str,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Check which gears have acknowledged a discovery.

        Returns dict with acknowledged gears, missing gears, and whether
        all required gears have acknowledged.
        """
        timeout = timeout_seconds or self._timeout_seconds
        all_events = self._event_bus.get_events_for_discovery(discovery_id)

        acknowledged_gears = set()
        for event in all_events:
            if event.event_type == DiscoveryEventType.DISCOVERY_ACKNOWLEDGED:
                acknowledged_gears.add(event.gear)

        missing = [g for g in self.REQUIRED_GEARS if g not in acknowledged_gears]

        return {
            "discovery_id": discovery_id,
            "acknowledged": sorted(acknowledged_gears),
            "missing": missing,
            "all_acknowledged": len(missing) == 0,
            "total_required": len(self.REQUIRED_GEARS),
        }

    def get_timeout_seconds(self) -> int:
        """Get the current acknowledgment timeout."""
        return self._timeout_seconds

    def set_timeout_seconds(self, seconds: int) -> None:
        """Set the acknowledgment timeout in seconds."""
        self._timeout_seconds = seconds

    def check_for_timeouts(
        self,
        discovery_id: str,
    ) -> Dict[str, Any]:
        """Check which gears have timed out on acknowledgment.

        Compares event timestamps against the configured timeout.
        Returns timed-out gear list and whether escalation is needed.
        """
        all_events = self._event_bus.get_events_for_discovery(discovery_id)
        now = datetime.now(timezone.utc)

        acknowledged_gears = set()
        broadcast_time = None

        for event in all_events:
            if event.event_type == DiscoveryEventType.DISCOVERY_ACKNOWLEDGED:
                acknowledged_gears.add(event.gear)
            if event.event_type == DiscoveryEventType.DISCOVERY_BROADCAST and broadcast_time is None:
                broadcast_time = datetime.fromisoformat(event.timestamp)

        timed_out = []
        for gear in self.REQUIRED_GEARS:
            if gear not in acknowledged_gears:
                if broadcast_time:
                    elapsed = (now - broadcast_time).total_seconds()
                    if elapsed > self._timeout_seconds:
                        timed_out.append(gear)

        return {
            "discovery_id": discovery_id,
            "timed_out": timed_out,
            "needs_escalation": len(timed_out) > 0,
            "timeout_seconds": self._timeout_seconds,
            "acknowledged": sorted(acknowledged_gears),
        }

    def retry_gear(
        self,
        discovery: DiscoveryRecord,
        gear: str,
    ) -> DiscoveryEvent:
        """Retry broadcasting to a specific gear that failed to acknowledge.

        Emits DISCOVERY_RETRY and a new DISCOVERY_BROADCAST for the gear.
        """
        retry_event = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_RETRY,
            discovery_id=discovery.discovery_id,
            mission_id=discovery.mission_id,
            correlation_id=discovery.correlation_id,
            causation_id=discovery.causation_id,
            producer="DISCOVERY_BROADCAST",
            receiver=gear,
            gear=gear,
            manager=discovery.source_manager_id,
            evidence_reference=",".join(discovery.evidence_references),
            data={"retry_gear": gear},
        )
        self._event_bus.publish(retry_event)

        broadcast_event = DiscoveryEvent.create(
            event_type=DiscoveryEventType.DISCOVERY_BROADCAST,
            discovery_id=discovery.discovery_id,
            mission_id=discovery.mission_id,
            correlation_id=discovery.correlation_id,
            causation_id=retry_event.event_id,
            producer="DISCOVERY_BROADCAST",
            receiver=gear,
            gear=gear,
            manager=discovery.source_manager_id,
            evidence_reference=",".join(discovery.evidence_references),
            data={
                "discovery_types": discovery.discovery_types,
                "materiality": discovery.materiality,
                "source_gear": discovery.source_gear,
                "source_agent": discovery.source_agent_id,
                "retry": True,
            },
        )
        self._event_bus.publish(broadcast_event)

        return broadcast_event
