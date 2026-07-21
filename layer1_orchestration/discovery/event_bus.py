"""
HERMES-PARALLEL-DISCOVERY-001 — Discovery Event Bus
====================================================
Central event infrastructure for the governed parallel discovery lifecycle.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Event Types
# ═══════════════════════════════════════════════════════════════

class DiscoveryEventType(str, Enum):
    """All required discovery events per Section 14."""
    DISCOVERY_DETECTED = "DISCOVERY_DETECTED"
    DISCOVERY_REGISTERED = "DISCOVERY_REGISTERED"
    DISCOVERY_BROADCAST = "DISCOVERY_BROADCAST"
    DISCOVERY_RECEIVED = "DISCOVERY_RECEIVED"
    DISCOVERY_ACKNOWLEDGED = "DISCOVERY_ACKNOWLEDGED"
    DISCOVERY_RETRY = "DISCOVERY_RETRY"

    SCRAPING_PERSPECTIVE_STARTED = "SCRAPING_PERSPECTIVE_STARTED"
    MINING_PERSPECTIVE_STARTED = "MINING_PERSPECTIVE_STARTED"
    SECURITY_PERSPECTIVE_STARTED = "SECURITY_PERSPECTIVE_STARTED"
    EVIDENCE_PERSPECTIVE_STARTED = "EVIDENCE_PERSPECTIVE_STARTED"

    PERSPECTIVE_SUBMITTED_TO_MANAGER = "PERSPECTIVE_SUBMITTED_TO_MANAGER"
    PERSPECTIVE_REWORK_REQUIRED = "PERSPECTIVE_REWORK_REQUIRED"
    PERSPECTIVE_MANAGER_APPROVED = "PERSPECTIVE_MANAGER_APPROVED"
    PERSPECTIVE_PUBLISHED = "PERSPECTIVE_PUBLISHED"
    PERSPECTIVE_UPDATED = "PERSPECTIVE_UPDATED"

    SCRAPING_PERSPECTIVE_PUBLISHED = "SCRAPING_PERSPECTIVE_PUBLISHED"
    MINING_PERSPECTIVE_PUBLISHED = "MINING_PERSPECTIVE_PUBLISHED"
    SECURITY_PERSPECTIVE_PUBLISHED = "SECURITY_PERSPECTIVE_PUBLISHED"
    EVIDENCE_PERSPECTIVE_PUBLISHED = "EVIDENCE_PERSPECTIVE_PUBLISHED"

    DISCOVERY_PERSPECTIVE_GATE_PASSED = "DISCOVERY_PERSPECTIVE_GATE_PASSED"
    DISCOVERY_PERSPECTIVE_GATE_FAILED = "DISCOVERY_PERSPECTIVE_GATE_FAILED"
    DECISION_ATTEMPT_BLOCKED = "DECISION_ATTEMPT_BLOCKED"
    DISCOVERY_SYNTHESIS_STARTED = "DISCOVERY_SYNTHESIS_STARTED"
    DISCOVERY_SYNTHESIS_COMPLETED = "DISCOVERY_SYNTHESIS_COMPLETED"
    NEXT_PHASE_DECISION_STARTED = "NEXT_PHASE_DECISION_STARTED"
    NEXT_PHASE_DECISION_COMPLETED = "NEXT_PHASE_DECISION_COMPLETED"


# ═══════════════════════════════════════════════════════════════
# Event
# ═══════════════════════════════════════════════════════════════

@dataclass
class DiscoveryEvent:
    """A single discovery event with full provenance."""
    event_id: str
    event_type: DiscoveryEventType
    discovery_id: str
    mission_id: str
    correlation_id: str
    causation_id: str
    producer: str  # gear or agent that produced this event
    receiver: str   # gear or agent that should receive this event
    gear: str       # associated gear
    manager: str    # associated manager
    evidence_reference: str
    timestamp: str
    data: dict = field(default_factory=dict)
    status: str = "FIRED"

    @classmethod
    def create(cls, **kwargs) -> DiscoveryEvent:
        if "event_id" not in kwargs:
            kwargs["event_id"] = str(uuid.uuid4())
        if "timestamp" not in kwargs:
            kwargs["timestamp"] = datetime.now(timezone.utc).isoformat()
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "producer": self.producer,
            "receiver": self.receiver,
            "gear": self.gear,
            "manager": self.manager,
            "evidence_reference": self.evidence_reference,
            "timestamp": self.timestamp,
            "data": self.data,
            "status": self.status,
        }


# ═══════════════════════════════════════════════════════════════
# Event Bus
# ═══════════════════════════════════════════════════════════════

class DiscoveryEventBus:
    """Central event bus for discovery lifecycle.

    Publishes events to subscribers. Maintains full event history
    with correlation, causation, producer, receiver, gear, manager,
    evidence reference, and timestamp.
    """

    def __init__(self):
        self._events: List[DiscoveryEvent] = []
        self._subscribers: Dict[str, List[Callable]] = {}  # event_type -> handlers
        self._event_index: Dict[str, List[DiscoveryEvent]] = {}  # discovery_id -> events

    def publish(self, event: DiscoveryEvent) -> None:
        """Publish an event and notify subscribers."""
        self._events.append(event)
        if event.discovery_id not in self._event_index:
            self._event_index[event.discovery_id] = []
        self._event_index[event.discovery_id].append(event)

        # Notify subscribers
        event_key = event.event_type.value
        if event_key in self._subscribers:
            for handler in self._subscribers[event_key]:
                handler(event)

    def subscribe(self, event_type: DiscoveryEventType, handler: Callable) -> None:
        """Subscribe to a specific event type."""
        key = event_type.value
        if key not in self._subscribers:
            self._subscribers[key] = []
        self._subscribers[key].append(handler)

    def get_events_for_discovery(self, discovery_id: str) -> List[DiscoveryEvent]:
        """Get all events for a specific discovery."""
        return self._event_index.get(discovery_id, [])

    def get_events_by_type(self, event_type: DiscoveryEventType) -> List[DiscoveryEvent]:
        """Get all events of a specific type."""
        return [e for e in self._events if e.event_type == event_type]

    def get_timeline(self) -> List[DiscoveryEvent]:
        """Get chronologically ordered events."""
        return sorted(self._events, key=lambda e: e.timestamp)

    def clear(self) -> None:
        """Clear all events."""
        self._events.clear()
        self._event_index.clear()
        self._subscribers.clear()

    @property
    def event_count(self) -> int:
        return len(self._events)

    def to_dict_list(self) -> List[dict]:
        return [e.to_dict() for e in self._events]
