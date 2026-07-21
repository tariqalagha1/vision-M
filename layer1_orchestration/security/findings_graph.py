"""
HERMES-FINDING-CHAIN-001 — Findings Graph
==========================================
Persistent directed graph of findings, edges, hypotheses, and chain state.
Survives restart. Queried before every new follow-up proposal.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .finding_node import (
    FindingNode, FindingEdge, ChainHypothesis, FindingChainImpact,
    ChainEvent, TargetedReconRequest,
    FindingNodeType, FindingEdgeType, HypothesisStatus,
    AuthorizationStatus, ValidationStatus, DispositionStatus,
    ChainEventType,
)


class FindingsGraph:
    """Persistent directed graph for finding chaining.

    Stores nodes, edges, hypotheses, impacts, events, contradictions,
    and authorization decisions. All operations are immutable-append —
    updates create new versions. State survives restart via JSON persistence.
    """

    def __init__(self, mission_id: str, storage_dir: str = "."):
        self.mission_id = mission_id
        self.storage_dir = storage_dir

        # Core storage
        self._nodes: Dict[str, FindingNode] = {}
        self._edges: Dict[str, FindingEdge] = {}
        self._hypotheses: Dict[str, ChainHypothesis] = {}
        self._impacts: Dict[str, FindingChainImpact] = {}
        self._events: List[ChainEvent] = []
        self._recon_requests: Dict[str, TargetedReconRequest] = {}
        self._contradictions: List[dict] = []
        self._decisions: List[dict] = []  # Manager decisions
        self._blocks: List[dict] = []  # Authorization blocks
        self._stop_log: List[dict] = []  # Stop condition log
        self._versions: Dict[str, list] = {}  # Chain version history

        # Indexes
        self._adjacency: Dict[str, Dict[str, List[FindingEdge]]] = {}  # node_id -> {edge_type -> [edges]}

        # Invariant state
        self._invariant_installed = False
        self._unauthorized_executions_blocked = 0

    # ═══════════════════════════════════════════════════════════
    # Invariant
    # ═══════════════════════════════════════════════════════════

    def install_invariant(self) -> None:
        """Install MYC-CHAIN-INV-001."""
        self._invariant_installed = True

    @property
    def invariant_active(self) -> bool:
        return self._invariant_installed

    # ═══════════════════════════════════════════════════════════
    # Node operations
    # ═══════════════════════════════════════════════════════════

    def add_node(self, node: FindingNode) -> FindingNode:
        if node.node_id in self._nodes:
            raise ValueError(f"Duplicate node: {node.node_id}")

        node.mission_id = self.mission_id
        node.updated_at = datetime.now(timezone.utc).isoformat()
        self._nodes[node.node_id] = node

        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = {}

        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id="",
            finding_id=node.node_id,
            hypothesis_id="",
            correlation_id=node.correlation_id,
            causation_id="",
            event_type=ChainEventType.FINDING_REGISTERED,
            producer_role=node.source_gear,
            receiver_role="FINDINGS_GRAPH",
            evidence_reference=",".join(node.evidence_ids),
            authorization_reference="",
            status="REGISTERED",
        ))
        return node

    def get_node(self, node_id: str) -> Optional[FindingNode]:
        return self._nodes.get(node_id)

    def update_node(self, node_id: str, **updates) -> FindingNode:
        node = self._nodes[node_id]
        for key, value in updates.items():
            if hasattr(node, key):
                setattr(node, key, value)
        node.updated_at = datetime.now(timezone.utc).isoformat()
        return node

    def get_nodes_by_type(self, node_type: FindingNodeType) -> List[FindingNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    # ═══════════════════════════════════════════════════════════
    # Edge operations
    # ═══════════════════════════════════════════════════════════

    def add_edge(self, edge: FindingEdge) -> FindingEdge:
        if edge.edge_id in self._edges:
            raise ValueError(f"Duplicate edge: {edge.edge_id}")

        # Validate nodes exist
        if edge.source_node_id not in self._nodes:
            raise ValueError(f"Source node not found: {edge.source_node_id}")
        if edge.target_node_id not in self._nodes:
            raise ValueError(f"Target node not found: {edge.target_node_id}")

        # Detect contradictions
        if edge.edge_type == FindingEdgeType.CONTRADICTS:
            self._contradictions.append({
                "contradiction_id": str(uuid.uuid4()),
                "edge_id": edge.edge_id,
                "source_node": edge.source_node_id,
                "target_node": edge.target_node_id,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "resolution": None,
            })

        edge.mission_id = self.mission_id
        edge.updated_at = datetime.now(timezone.utc).isoformat()
        self._edges[edge.edge_id] = edge

        # Update adjacency
        if edge.edge_type.value not in self._adjacency.get(edge.source_node_id, {}):
            self._adjacency.setdefault(edge.source_node_id, {})[edge.edge_type.value] = []
        self._adjacency[edge.source_node_id][edge.edge_type.value].append(edge)

        return edge

    def get_edge(self, edge_id: str) -> Optional[FindingEdge]:
        return self._edges.get(edge_id)

    def get_edges_for_node(self, node_id: str, edge_type: Optional[FindingEdgeType] = None) -> List[FindingEdge]:
        adj = self._adjacency.get(node_id, {})
        if edge_type:
            return adj.get(edge_type.value, [])
        result = []
        for edges in adj.values():
            result.extend(edges)
        return result

    def get_edges_between(self, source_id: str, target_id: str) -> List[FindingEdge]:
        result = []
        for edge in self._edges.values():
            if edge.source_node_id == source_id and edge.target_node_id == target_id:
                result.append(edge)
        return result

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ═══════════════════════════════════════════════════════════
    # Hypothesis operations
    # ═══════════════════════════════════════════════════════════

    def add_hypothesis(self, hypothesis: ChainHypothesis) -> ChainHypothesis:
        if hypothesis.hypothesis_id in self._hypotheses:
            raise ValueError(f"Duplicate hypothesis: {hypothesis.hypothesis_id}")

        hypothesis.mission_id = self.mission_id
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis

        # Version tracking
        if hypothesis.hypothesis_id not in self._versions:
            self._versions[hypothesis.hypothesis_id] = []
        self._versions[hypothesis.hypothesis_id].append({
            "status": hypothesis.status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id="",
            finding_id=",".join(hypothesis.parent_finding_ids),
            hypothesis_id=hypothesis.hypothesis_id,
            correlation_id="",
            causation_id="",
            event_type=ChainEventType.CHAIN_HYPOTHESIS_CREATED,
            producer_role=hypothesis.proposed_by,
            receiver_role="FINDINGS_GRAPH",
            evidence_reference="",
            authorization_reference="",
            status=hypothesis.status,
        ))
        return hypothesis

    def update_hypothesis_status(self, hypothesis_id: str, new_status: str, reason: str = "") -> ChainHypothesis:
        hyp = self._hypotheses[hypothesis_id]
        old_status = hyp.status
        hyp.status = new_status
        if new_status in ("APPROVED", "REJECTED", "DEFERRED", "EXECUTED", "VALIDATED"):
            hyp.decided_at = datetime.now(timezone.utc).isoformat()

        # Version tracking
        self._versions[hypothesis_id].append({
            "status": new_status,
            "previous_status": old_status,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Determine event type
        event_map = {
            "UNDER_REVIEW": ChainEventType.CHAIN_HYPOTHESIS_REVIEW_STARTED,
            "APPROVED": ChainEventType.CHAIN_HYPOTHESIS_APPROVED,
            "REJECTED": ChainEventType.CHAIN_HYPOTHESIS_REJECTED,
            "BLOCKED_BY_SCOPE": ChainEventType.CHAIN_BLOCKED_BY_SCOPE,
            "BLOCKED_BY_AUTHORIZATION": ChainEventType.CHAIN_BLOCKED_BY_AUTHORIZATION,
            "VALIDATED": ChainEventType.CHAIN_EDGE_VALIDATED,
        }
        event_type = event_map.get(new_status, ChainEventType.CHAIN_HYPOTHESIS_REVIEW_STARTED)

        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id="",
            finding_id=",".join(hyp.parent_finding_ids),
            hypothesis_id=hypothesis_id,
            correlation_id="",
            causation_id="",
            event_type=event_type,
            producer_role="CHAIN_MANAGER",
            receiver_role="FINDINGS_GRAPH",
            evidence_reference="",
            authorization_reference="",
            status=new_status,
            reason=reason,
        ))

        return hyp

    def get_hypothesis(self, hypothesis_id: str) -> Optional[ChainHypothesis]:
        return self._hypotheses.get(hypothesis_id)

    def get_hypotheses_for_finding(self, finding_id: str) -> List[ChainHypothesis]:
        return [h for h in self._hypotheses.values() if finding_id in h.parent_finding_ids]

    def get_hypotheses_by_status(self, status: str) -> List[ChainHypothesis]:
        return [h for h in self._hypotheses.values() if h.status == status]

    @property
    def hypothesis_count(self) -> int:
        return len(self._hypotheses)

    # ═══════════════════════════════════════════════════════════
    # Chain impact
    # ═══════════════════════════════════════════════════════════

    def add_impact(self, impact: FindingChainImpact) -> FindingChainImpact:
        self._impacts[impact.chain_id] = impact
        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id=impact.chain_id,
            finding_id=",".join(impact.finding_ids),
            hypothesis_id="",
            correlation_id="",
            causation_id="",
            event_type=ChainEventType.CHAIN_IMPACT_RECALCULATED,
            producer_role="CHAIN_IMPACT_ENGINE",
            receiver_role="FINDINGS_GRAPH",
            evidence_reference="",
            authorization_reference="",
            status="RECALCULATED",
        ))
        return impact

    def get_impact(self, chain_id: str) -> Optional[FindingChainImpact]:
        return self._impacts.get(chain_id)

    # ═══════════════════════════════════════════════════════════
    # Recon requests
    # ═══════════════════════════════════════════════════════════

    def add_recon_request(self, request: TargetedReconRequest) -> TargetedReconRequest:
        self._recon_requests[request.request_id] = request
        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id="",
            finding_id=",".join(request.trigger_finding_ids),
            hypothesis_id="",
            correlation_id="",
            causation_id="",
            event_type=ChainEventType.TARGETED_RECON_REQUESTED,
            producer_role="CHAIN_PLANNER",
            receiver_role="RECON_COORDINATOR",
            evidence_reference="",
            authorization_reference=request.authorization_reference,
            status="REQUESTED",
        ))
        return request

    # ═══════════════════════════════════════════════════════════
    # Decisions, blocks, stops
    # ═══════════════════════════════════════════════════════════

    def record_decision(self, decision: dict) -> None:
        self._decisions.append(decision)

    def record_block(self, block: dict) -> None:
        self._blocks.append(block)
        self._unauthorized_executions_blocked += 1

        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id=block.get("chain_id", ""),
            finding_id=block.get("finding_id", ""),
            hypothesis_id=block.get("hypothesis_id", ""),
            correlation_id="",
            causation_id="",
            event_type=ChainEventType.CHAIN_BLOCKED_BY_AUTHORIZATION,
            producer_role="AUTHORIZATION_GATE",
            receiver_role="CHAIN_EXECUTION_GUARD",
            evidence_reference="",
            authorization_reference=block.get("authorization_reference", ""),
            status="BLOCKED",
            reason=block.get("reason", ""),
        ))

    def record_stop(self, stop: dict) -> None:
        self._stop_log.append(stop)

        self._emit(ChainEvent.create(
            mission_id=self.mission_id,
            chain_id=stop.get("chain_id", ""),
            finding_id=stop.get("finding_id", ""),
            hypothesis_id=stop.get("hypothesis_id", ""),
            correlation_id="",
            causation_id="",
            event_type=ChainEventType.CHAIN_VALIDATION_STOPPED,
            producer_role="EXECUTION_GUARD",
            receiver_role="FINDINGS_GRAPH",
            evidence_reference="",
            authorization_reference="",
            status="STOPPED",
            reason=stop.get("reason", ""),
        ))

    @property
    def blocked_count(self) -> int:
        return self._unauthorized_executions_blocked

    # ═══════════════════════════════════════════════════════════
    # Events
    # ═══════════════════════════════════════════════════════════

    def _emit(self, event: ChainEvent) -> None:
        self._events.append(event)

    def get_events(self) -> List[ChainEvent]:
        return list(self._events)

    # ═══════════════════════════════════════════════════════════
    # Queries
    # ═══════════════════════════════════════════════════════════

    def get_validated_edges(self) -> List[FindingEdge]:
        return [e for e in self._edges.values() if e.status == "VALIDATED"]

    def get_rejected_edges(self) -> List[FindingEdge]:
        return [e for e in self._edges.values() if e.status == "REJECTED"]

    def get_contradictions(self) -> List[dict]:
        return list(self._contradictions)

    def get_trust_boundaries_crossed(self) -> List[str]:
        boundaries = set()
        for edge in self._edges.values():
            if edge.edge_type == FindingEdgeType.CROSSES_TRUST_BOUNDARY:
                src = self._nodes.get(edge.source_node_id)
                tgt = self._nodes.get(edge.target_node_id)
                if src and tgt:
                    boundaries.update(src.affected_trust_boundaries)
                    boundaries.update(tgt.affected_trust_boundaries)
        return sorted(boundaries)

    def get_descendants(self, node_id: str, depth: int = 10) -> List[FindingNode]:
        """BFS to find all descendant nodes."""
        visited = set()
        result = []
        queue = [(node_id, 0)]
        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)
            if current != node_id and current in self._nodes:
                result.append(self._nodes[current])
            adj = self._adjacency.get(current, {})
            for edges in adj.values():
                for edge in edges:
                    if edge.target_node_id not in visited:
                        queue.append((edge.target_node_id, d + 1))
        return result

    # ── Phase 1: Ancestors ──

    def get_ancestors(self, node_id: str, depth: int = 10) -> List[FindingNode]:
        """BFS upstream to find all ancestor nodes (who points to this node)."""
        visited = set()
        result = []
        queue = [(node_id, 0)]
        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)
            if current != node_id and current in self._nodes:
                result.append(self._nodes[current])
            # Find all edges that point TO current
            for edge in self._edges.values():
                if edge.target_node_id == current and edge.source_node_id not in visited:
                    queue.append((edge.source_node_id, d + 1))
        return result

    # ── Phase 1: Visited-work registry ──

    def _init_visited_work(self) -> None:
        """Initialize the visited-work set for loop prevention."""
        if not hasattr(self, '_visited_work_set'):
            self._visited_work_set: set = set()

    def check_and_register_work(
        self, work_identity: str
    ) -> bool:
        """Check if a work unit was already visited. If not, register it.

        Returns True if the work is NEW (not yet visited), False if duplicate.
        """
        self._init_visited_work()
        if work_identity in self._visited_work_set:
            return False
        self._visited_work_set.add(work_identity)
        return True

    def get_visited_work_count(self) -> int:
        self._init_visited_work()
        return len(self._visited_work_set)

    def detect_severity_inflation(self) -> List[dict]:
        """Detect chains where severity exceeds evidence."""
        inflations = []
        for node in self._nodes.values():
            if node.node_type == FindingNodeType.IMPACT:
                edges_in = self.get_edges_for_node(node.node_id)
                supporting = [e for e in edges_in if e.edge_type in (
                    FindingEdgeType.SUPPORTS, FindingEdgeType.VALIDATED_BY
                )]
                if node.severity in ("critical", "high") and len(supporting) == 0:
                    inflations.append({
                        "node_id": node.node_id,
                        "title": node.title,
                        "severity": node.severity,
                        "supporting_edges": len(supporting),
                        "issue": "SEVERITY_WITHOUT_SUPPORTING_EVIDENCE",
                    })
        return inflations

    # ═══════════════════════════════════════════════════════════
    # Persistence
    # ═══════════════════════════════════════════════════════════

    def save(self, filepath: Optional[str] = None) -> str:
        if filepath is None:
            filepath = os.path.join(self.storage_dir, "findings_graph.json")

        data = {
            "mission_id": self.mission_id,
            "invariant_installed": self._invariant_installed,
            "unauthorized_executions_blocked": self._unauthorized_executions_blocked,
            "nodes": {k: v.to_dict() for k, v in self._nodes.items()},
            "edges": {k: v.to_dict() for k, v in self._edges.items()},
            "hypotheses": {k: v.to_dict() for k, v in self._hypotheses.items()},
            "impacts": {k: v.to_dict() for k, v in self._impacts.items()},
            "recon_requests": {k: v.to_dict() for k, v in self._recon_requests.items()},
            "events": [e.to_dict() for e in self._events],
            "contradictions": self._contradictions,
            "decisions": self._decisions,
            "blocks": self._blocks,
            "stop_log": self._stop_log,
            "versions": self._versions,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    @classmethod
    def load(cls, filepath: str) -> FindingsGraph:
        with open(filepath, "r") as f:
            data = json.load(f)

        graph = cls(mission_id=data["mission_id"], storage_dir=os.path.dirname(filepath))
        graph._invariant_installed = data.get("invariant_installed", False)
        graph._unauthorized_executions_blocked = data.get("unauthorized_executions_blocked", 0)

        # Restore nodes
        for node_id, node_data in data.get("nodes", {}).items():
            node_data["node_type"] = FindingNodeType(node_data["node_type"])
            graph._nodes[node_id] = FindingNode(**node_data)

        # Restore edges
        for edge_id, edge_data in data.get("edges", {}).items():
            edge_data["edge_type"] = FindingEdgeType(edge_data["edge_type"])
            graph._edges[edge_id] = FindingEdge(**edge_data)
            # Rebuild adjacency
            e = graph._edges[edge_id]
            graph._adjacency.setdefault(e.source_node_id, {}).setdefault(e.edge_type.value, []).append(e)

        # Restore hypotheses
        for hid, hdata in data.get("hypotheses", {}).items():
            graph._hypotheses[hid] = ChainHypothesis(**hdata)

        # Restore impacts
        for cid, cdata in data.get("impacts", {}).items():
            graph._impacts[cid] = FindingChainImpact(**cdata)

        # Restore recon requests
        for rid, rdata in data.get("recon_requests", {}).items():
            graph._recon_requests[rid] = TargetedReconRequest(**rdata)

        # Restore events
        for edata in data.get("events", []):
            edata["event_type"] = ChainEventType(edata["event_type"])
            graph._events.append(ChainEvent(**edata))

        # Restore lists
        graph._contradictions = data.get("contradictions", [])
        graph._decisions = data.get("decisions", [])
        graph._blocks = data.get("blocks", [])
        graph._stop_log = data.get("stop_log", [])
        graph._versions = data.get("versions", {})

        return graph

    # ═══════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════

    def summary(self) -> dict:
        return {
            "mission_id": self.mission_id,
            "invariant_installed": self._invariant_installed,
            "nodes": self.node_count,
            "edges": self.edge_count,
            "validated_edges": len(self.get_validated_edges()),
            "rejected_edges": len(self.get_rejected_edges()),
            "hypotheses": self.hypothesis_count,
            "contradictions": len(self._contradictions),
            "blocks": self._unauthorized_executions_blocked,
            "stops": len(self._stop_log),
            "events": len(self._events),
            "trust_boundaries_crossed": len(self.get_trust_boundaries_crossed()),
        }
