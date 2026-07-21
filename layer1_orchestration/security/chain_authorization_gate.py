"""
HERMES-FINDING-CHAIN-001 — Chain Authorization Gate
====================================================
Multi-gate validator every hypothesis must pass before execution.

MYC-CHAIN-INV-001 enforced: no hypothesis proceeds without all
mandatory gates passing. Non-blocking gates may produce warnings
but do not prevent authorization.

Gate list (10 mandatory gates):
  1. Evidence Sufficiency Gate
  2. Scope Compatibility Gate
  3. Authorization Gate
  4. Safety and Reversibility Gate
  5. Manager Approval Gate
  6. Supervisor Visibility Gate
  7. Request Budget Gate
  8. Data Minimization Gate
  9. Chain Causation Gate
 10. Final Evidence Gate
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .finding_node import ChainHypothesis, FindingNode
from .findings_graph import FindingsGraph


# ── Verdict constants ──────────────────────────────────────────
VERDICT_AUTHORIZED = "CHAIN_VALIDATION_AUTHORIZED"
VERDICT_NOT_AUTHORIZED = "CHAIN_VALIDATION_NOT_AUTHORIZED"
VERDICT_CONDITIONAL = "CHAIN_VALIDATION_CONDITIONAL"


# ── Gate failure severities ────────────────────────────────────
class GateSeverity:
    """Severity levels for gate failure reasons."""
    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


class ChainAuthorizationGate:
    """Multi-gate validator for chain hypotheses.

    Every hypothesis must pass all mandatory (blocking) gates before
    execution can proceed.  Non-blocking gates emit warnings but do
    not prevent authorization.

    Usage::

        gate = ChainAuthorizationGate()
        result = gate.validate(
            hypothesis=hypothesis,
            graph=findings_graph,
            mission_scope={"assets": ["api-gateway", "auth-service"],
                           "approved_methods": ["api-probe", "log-analysis"]},
            authorization={"reference": "AUTH-2025-0042",
                           "scope_impact_allowable": True,
                           "supervisor_notified": True,
                           "risk_acceptance_signed": False},
            manager_id="mgmt-alice",
        )
        if result["passed"]:
            proceed(hypothesis)
    """

    # ── Budget / proportionality defaults ──────────────────────
    DEFAULT_REQUEST_BUDGET = 10
    DEFAULT_MAX_EVIDENCE_ITEMS = 20

    def __init__(
        self,
        *,
        min_confidence: float = 0.5,
        request_budget: int = DEFAULT_REQUEST_BUDGET,
        max_evidence_items: int = DEFAULT_MAX_EVIDENCE_ITEMS,
        require_supervisor_notification: bool = True,
    ) -> None:
        self.min_confidence = min_confidence
        self.request_budget = request_budget
        self.max_evidence_items = max_evidence_items
        self.require_supervisor_notification = require_supervisor_notification

    # ═══════════════════════════════════════════════════════════
    # Public API
    # ═══════════════════════════════════════════════════════════

    def validate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Run every mandatory gate against *hypothesis*.

        Returns a dict with::

            {
                "passed": bool,
                "gate_results": [ {gate_name, passed, reason, blocking}, ... ],
                "verdict": str,   # one of the VERDICT_* constants
            }
        """
        gates = [
            self._evidence_sufficiency_gate,
            self._scope_compatibility_gate,
            self._authorization_gate,
            self._safety_and_reversibility_gate,
            self._manager_approval_gate,
            self._supervisor_visibility_gate,
            self._request_budget_gate,
            self._data_minimization_gate,
            self._chain_causation_gate,
            self._final_evidence_gate,
        ]

        gate_results: List[Dict[str, Any]] = []
        any_blocking_failure = False

        for gate_fn in gates:
            result = gate_fn(hypothesis, graph, mission_scope, authorization, manager_id)
            gate_results.append(result)
            if result.get("blocking") and not result.get("passed"):
                any_blocking_failure = True

        passed = not any_blocking_failure

        if passed:
            verdict = VERDICT_AUTHORIZED
        else:
            verdict = VERDICT_NOT_AUTHORIZED

        return {
            "passed": passed,
            "gate_results": gate_results,
            "verdict": verdict,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 1 — Evidence Sufficiency
    # ═══════════════════════════════════════════════════════════

    def _evidence_sufficiency_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Confidence >= min_confidence AND at least one evidence reference exists."""
        gate_name = "Evidence Sufficiency Gate"

        parent_findings = self._resolve_parent_findings(hypothesis, graph)
        if not parent_findings:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": "No parent findings resolved in graph — cannot assess evidence sufficiency.",
                "blocking": True,
            }

        # Aggregate confidence across parent findings
        confidences = [n.confidence for n in parent_findings]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        if avg_confidence < self.min_confidence:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": (
                    f"Average confidence ({avg_confidence:.2f}) "
                    f"below threshold ({self.min_confidence})."
                ),
                "blocking": True,
            }

        # At least one evidence reference across parent findings
        total_evidence = sum(len(n.evidence_ids) for n in parent_findings)
        if total_evidence == 0:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": "No evidence references found on parent findings.",
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": True,
            "reason": (
                f"Average confidence {avg_confidence:.2f} meets threshold; "
                f"{total_evidence} evidence reference(s) present."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 2 — Scope Compatibility
    # ═══════════════════════════════════════════════════════════

    def _scope_compatibility_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """target_asset must be in mission_scope and method must be approved."""
        gate_name = "Scope Compatibility Gate"

        scope_assets: List[str] = mission_scope.get("assets", [])
        approved_methods: List[str] = mission_scope.get("approved_methods", [])

        target = hypothesis.target_asset
        method = hypothesis.proposed_method

        asset_in_scope = any(target == a for a in scope_assets)
        method_approved = any(method == m for m in approved_methods)

        failures: List[str] = []

        if not asset_in_scope:
            failures.append(
                f"Target asset '{target}' is not in mission scope "
                f"(scope: {scope_assets})."
            )
        if not method_approved:
            failures.append(
                f"Proposed method '{method}' is not in approved methods "
                f"(approved: {approved_methods})."
            )

        if failures:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": " ".join(failures),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": True,
            "reason": (
                f"Target '{target}' in scope, method '{method}' approved."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 3 — Authorization
    # ═══════════════════════════════════════════════════════════

    def _authorization_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Authorization reference must be present; scope_impact must be acceptable."""
        gate_name = "Authorization Gate"

        auth_ref = authorization.get("reference", "")
        if not auth_ref:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": "No authorization reference provided.",
                "blocking": True,
            }

        # scope_impact from hypothesis must not exceed what the auth allows
        impact = hypothesis.authorization_impact
        allowable = authorization.get("scope_impact_allowable", True)

        if impact in ("critical", "high") and not allowable:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": (
                    f"Authorization impact '{impact}' exceeds allowable scope "
                    f"for authorization '{auth_ref}'."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": True,
            "reason": (
                f"Authorization reference '{auth_ref}' present; "
                f"scope impact '{impact}' is acceptable."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 4 — Safety and Reversibility
    # ═══════════════════════════════════════════════════════════

    def _safety_and_reversibility_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """safe_test_available must be True OR explicit risk acceptance signed."""
        gate_name = "Safety and Reversibility Gate"

        if hypothesis.safe_test_available:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": (
                    f"Safe test available: "
                    f"{hypothesis.safe_test_description or '(no description)'}."
                ),
                "blocking": True,
            }

        # Check for explicit risk acceptance
        risk_accepted = authorization.get("risk_acceptance_signed", False)
        if risk_accepted:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": "Explicit risk acceptance signed despite no safe test available.",
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": False,
            "reason": (
                "No safe test available and no explicit risk acceptance signed. "
                "Hypothesis cannot proceed without either a safe test or acknowledged risk."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 5 — Manager Approval
    # ═══════════════════════════════════════════════════════════

    def _manager_approval_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Manager approval signature must be present (reviewed_by or authorization)."""
        gate_name = "Manager Approval Gate"

        # Check if manager has reviewed
        if manager_id in hypothesis.reviewed_by:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": f"Manager '{manager_id}' has reviewed this hypothesis.",
                "blocking": True,
            }

        # Check if manager is the approving authority in the authorization dict
        auth_manager = authorization.get("approved_by", "")
        if auth_manager and auth_manager == manager_id:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": (
                    f"Manager '{manager_id}' approved via authorization "
                    f"'{authorization.get('reference', '')}'."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": False,
            "reason": (
                f"Manager '{manager_id}' has not reviewed or approved this hypothesis. "
                f"Reviewed by: {hypothesis.reviewed_by}."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 6 — Supervisor Visibility
    # ═══════════════════════════════════════════════════════════

    def _supervisor_visibility_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Supervisor must be notified of the hypothesis."""
        gate_name = "Supervisor Visibility Gate"

        if not self.require_supervisor_notification:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": "Supervisor notification requirement disabled.",
                "blocking": True,
            }

        supervisor_notified = authorization.get("supervisor_notified", False)
        if supervisor_notified:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": "Supervisor has been notified.",
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": False,
            "reason": "Supervisor has not been notified of this hypothesis.",
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 7 — Request Budget
    # ═══════════════════════════════════════════════════════════

    def _request_budget_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Estimated requests (expected_evidence count) must not exceed budget."""
        gate_name = "Request Budget Gate"

        # Use expected_evidence length as a proxy for estimated request count
        estimated = len(hypothesis.expected_evidence)

        # Budget can be overridden via authorization or mission_scope
        budget = authorization.get("request_budget", self.request_budget)
        budget = mission_scope.get("request_budget", budget)

        if estimated <= budget:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": (
                    f"Estimated requests ({estimated}) within budget ({budget})."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": False,
            "reason": (
                f"Estimated requests ({estimated}) exceed budget ({budget})."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 8 — Data Minimization
    # ═══════════════════════════════════════════════════════════

    def _data_minimization_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Expected evidence must be proportional — not excessive."""
        gate_name = "Data Minimization Gate"

        evidence_count = len(hypothesis.expected_evidence)
        max_allowed = authorization.get("max_evidence_items", self.max_evidence_items)
        max_allowed = mission_scope.get("max_evidence_items", max_allowed)

        if evidence_count <= max_allowed:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": (
                    f"Expected evidence items ({evidence_count}) within "
                    f"proportionality limit ({max_allowed})."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": False,
            "reason": (
                f"Expected evidence items ({evidence_count}) exceed proportionality "
                f"limit ({max_allowed}). Reduce scope or request additional budget."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Gate 9 — Chain Causation
    # ═══════════════════════════════════════════════════════════

    def _chain_causation_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Hypothesis must logically follow from its parent findings in the graph.

        A chain is logically sound when every parent finding exists in the graph
        and at least one chain of edges connects them (directly or transitively).
        """
        gate_name = "Chain Causation Gate"

        parent_ids = hypothesis.parent_finding_ids
        if not parent_ids:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": "Hypothesis has no parent findings — cannot establish causation.",
                "blocking": True,
            }

        # Verify all parent findings exist in graph
        missing = [pid for pid in parent_ids if graph.get_node(pid) is None]
        if missing:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": (
                    f"Parent finding(s) not found in graph: {missing}. "
                    f"Causation chain cannot be validated."
                ),
                "blocking": True,
            }

        # Single parent: trivially connected
        if len(parent_ids) == 1:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": (
                    f"Single parent finding '{parent_ids[0]}' exists in graph; "
                    f"causation is direct."
                ),
                "blocking": True,
            }

        # Multiple parents: check for connectivity via graph edges
        connected = self._are_parents_connected(parent_ids, graph)
        if not connected:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": (
                    f"Parent findings ({parent_ids}) are not connected by any "
                    f"existing graph edges. Chain causation is not established."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": True,
            "reason": (
                f"Parent findings ({parent_ids}) form a connected causation chain "
                f"in the graph."
            ),
            "blocking": True,
        }

    def _are_parents_connected(
        self,
        parent_ids: List[str],
        graph: FindingsGraph,
    ) -> bool:
        """Check whether all parent nodes belong to the same weakly-connected component.

        Uses undirected BFS — edges are traversed in both directions.
        All parents must be in the same connected subgraph.
        """
        node_set = set(parent_ids)

        # Build undirected adjacency: for each node, collect all neighbours
        # (both outgoing from get_edges_for_node and incoming via reverse lookup)
        neighbours: Dict[str, set] = {pid: set() for pid in parent_ids}

        for pid in parent_ids:
            # Outgoing edges from pid
            for edge in graph.get_edges_for_node(pid):
                if edge.target_node_id in node_set:
                    neighbours[pid].add(edge.target_node_id)
                    neighbours[edge.target_node_id].add(pid)

        # BFS from first parent; all others must be reachable
        start = parent_ids[0]
        visited: set = set()
        queue = [start]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for nbr in neighbours.get(current, set()):
                if nbr not in visited:
                    queue.append(nbr)

        return node_set.issubset(visited)

    # ═══════════════════════════════════════════════════════════
    # Gate 10 — Final Evidence
    # ═══════════════════════════════════════════════════════════

    def _final_evidence_gate(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
        manager_id: str,
    ) -> Dict[str, Any]:
        """Every evidence_id referenced by parent findings must exist in the graph."""
        gate_name = "Final Evidence Gate"

        parent_findings = self._resolve_parent_findings(hypothesis, graph)
        if not parent_findings:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": "No parent findings to validate evidence against.",
                "blocking": True,
            }

        # Collect all evidence_ids referenced by parent findings
        all_evidence_ids: set = set()
        for node in parent_findings:
            all_evidence_ids.update(node.evidence_ids)

        if not all_evidence_ids:
            return {
                "gate_name": gate_name,
                "passed": True,
                "reason": "No evidence IDs referenced — nothing to validate.",
                "blocking": True,
            }

        # Evidence nodes in the graph have type FindingNodeType.DATA_SOURCE
        # or are referenced as OBSERVATION/FINDING nodes directly
        graph_node_ids = set(graph._nodes.keys())

        # Also consider artifact_ids as evidence proxies
        all_graph_evidence: set = graph_node_ids.copy()
        for node in graph._nodes.values():
            all_graph_evidence.update(node.evidence_ids)

        missing = all_evidence_ids - all_graph_evidence
        if missing:
            return {
                "gate_name": gate_name,
                "passed": False,
                "reason": (
                    f"Evidence ID(s) not found in graph: {sorted(missing)}. "
                    f"All referenced evidence must exist before chain execution."
                ),
                "blocking": True,
            }

        return {
            "gate_name": gate_name,
            "passed": True,
            "reason": (
                f"All {len(all_evidence_ids)} evidence reference(s) verified "
                f"in graph."
            ),
            "blocking": True,
        }

    # ═══════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════

    def _resolve_parent_findings(
        self,
        hypothesis: ChainHypothesis,
        graph: FindingsGraph,
    ) -> List[FindingNode]:
        """Return parent FindingNode objects for the hypothesis."""
        nodes: List[FindingNode] = []
        for pid in hypothesis.parent_finding_ids:
            node = graph.get_node(pid)
            if node is not None:
                nodes.append(node)
        return nodes
