"""
HERMES-FINDING-CHAIN-001 — Finding Chain Planner
==================================================
Generates bounded, evidence-linked chain hypotheses from validated findings.

Key design principles:
- Every hypothesis is bounded: it proposes a specific, testable next step,
  never a blind "rescan everything."
- All hypotheses link back to source evidence through parent_finding_ids.
- The planner uses approved chaining patterns A–F and never invents
  unauthorized or broad-spectrum tests.
- Safety-gate questions are evaluated before any hypothesis is emitted.

MYC-CHAIN-INV-001 enforced: no hypothesis requests execution outside
authorization scope.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .finding_node import (
    FindingNode,
    FindingEdge,
    ChainHypothesis,
    FindingNodeType,
    FindingEdgeType,
    HypothesisStatus,
)
from .findings_graph import FindingsGraph


# ═══════════════════════════════════════════════════════════════
# Chaining-pattern definitions (approved patterns A–F)
# ═══════════════════════════════════════════════════════════════

@dataclass
class ChainingPattern:
    """A single approved chaining pattern with its triggering signals,
    proposed method constraints, and safety requirements."""

    pattern_id: str
    label: str
    trigger_keywords: List[str]
    trigger_node_types: List[FindingNodeType]
    rationale_template: str
    expected_observation_template: str
    proposed_method: str
    expected_evidence: List[str]
    risk_level: str
    scope_impact: str
    authorization_impact: str
    trust_boundary_impact: str
    safe_test_available: bool
    safe_test_description: str
    title_template: str


# Approved chaining patterns per the spec (A–F)
APPROVED_PATTERNS: List[ChainingPattern] = [
    ChainingPattern(
        pattern_id="A",
        label="Sensitive-data exposure → access-impact hypothesis",
        trigger_keywords=[
            "sensitive", "exposure", "data leak", "information disclosure",
            "pii", "credentials", "secret", "token", "api key", "password",
            "sensitive data", "data exposure", "leaked",
        ],
        trigger_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        rationale_template=(
            "A finding of sensitive-data exposure on {asset} suggests that "
            "unauthorized access to protected data may be possible. This hypothesis "
            "proposes a controlled access test to determine whether the exposure "
            "represents an exploitable path to additional sensitive data."
        ),
        expected_observation_template=(
            "Using synthetic credentials on the designated test service {asset}, "
            "verify whether the exposed data path can be traversed to reach "
            "additional protected resources beyond the originally reported scope."
        ),
        proposed_method=(
            "Controlled access test using synthetic tokens on designated test "
            "service only. No production credentials or real user data involved."
        ),
        expected_evidence=[
            "Access granted/denied log entry",
            "Scope of accessible resources compared against authorization baseline",
            "No production data accessed during test",
        ],
        risk_level="medium",
        scope_impact="expands_understanding",
        authorization_impact="requires_test_tenant_auth",
        trust_boundary_impact="may_cross_data_access_boundary",
        safe_test_available=True,
        safe_test_description=(
            "Synthetic token test on designated test service — no production "
            "credentials, no real user data, fully isolated from live systems."
        ),
        title_template="Access-impact test following {finding_title}",
    ),
    ChainingPattern(
        pattern_id="B",
        label="Object-level auth weakness → exposure-scope sampling",
        trigger_keywords=[
            "idor", "object-level", "authorization", "access control",
            "insecure direct object reference", "broken access control",
            "object reference", "horizontal privilege", "vertical privilege",
            "auth bypass", "authorization bypass",
        ],
        trigger_node_types=[FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION],
        rationale_template=(
            "A finding of object-level authorization weakness on {asset} raises "
            "the question of exposure scope. This hypothesis proposes a bounded "
            "sampling test using a fixed, pre-approved set of object identifiers "
            "to determine the breadth of the authorization gap."
        ),
        expected_observation_template=(
            "Using fixed, pre-approved object IDs on {asset}, observe whether "
            "access to objects outside the authorized scope is granted, and "
            "document the scope of accessible objects."
        ),
        proposed_method=(
            "Exposure-scope sampling with a fixed list of pre-approved object "
            "identifiers. No brute-force or iterative discovery. Read-only "
            "access verification only."
        ),
        expected_evidence=[
            "Per-object access granted/denied results",
            "Enumeration of exposed object scope",
            "No modification or deletion of any object",
        ],
        risk_level="medium",
        scope_impact="expands_understanding",
        authorization_impact="requires_scope_verification",
        trust_boundary_impact="may_cross_user_data_boundary",
        safe_test_available=True,
        safe_test_description=(
            "Fixed-ID sampling on designated test tenant — pre-approved object "
            "IDs only, read-only verification, no data modification."
        ),
        title_template="Exposure-scope assessment following {finding_title}",
    ),
    ChainingPattern(
        pattern_id="C",
        label="Verbose error → technology hypothesis",
        trigger_keywords=[
            "verbose error", "stack trace", "debug", "error message",
            "exception", "traceback", "detailed error", "information leakage",
            "error disclosure", "server error",
        ],
        trigger_node_types=[FindingNodeType.OBSERVATION, FindingNodeType.FINDING],
        rationale_template=(
            "Verbose error messages on {asset} may reveal underlying technology "
            "stack details. This hypothesis proposes non-destructive checks to "
            "identify the technology stack without exploiting the error condition."
        ),
        expected_observation_template=(
            "Using non-destructive fingerprinting techniques on {asset}, determine "
            "the technology stack (framework, version, server type) without "
            "triggering error conditions or causing service disruption."
        ),
        proposed_method=(
            "Non-destructive technology fingerprinting — HTTP header inspection, "
            "static file checks, standard endpoint probing. No injection, no "
            "error triggering, no active attack techniques."
        ),
        expected_evidence=[
            "Technology stack identification (framework, version)",
            "Comparison against known-vulnerable version database",
            "No error conditions triggered during test",
        ],
        risk_level="low",
        scope_impact="technology_inventory",
        authorization_impact="none",
        trust_boundary_impact="none",
        safe_test_available=True,
        safe_test_description=(
            "Passive fingerprinting only — standard HTTP requests, no injection, "
            "no error triggering, no disruption to service."
        ),
        title_template="Technology-stack hypothesis from {finding_title}",
    ),
    ChainingPattern(
        pattern_id="D",
        label="Auth-validation weakness → controlled authorization test",
        trigger_keywords=[
            "auth", "authentication", "jwt", "session", "token validation",
            "missing authentication", "broken authentication", "session fixation",
            "credential stuffing", "brute force", "weak password policy",
        ],
        trigger_node_types=[FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION],
        rationale_template=(
            "A finding of authentication-validation weakness on {asset} may allow "
            "unauthorized access. This hypothesis proposes a controlled test using "
            "synthetic tokens within a designated test tenant to validate the "
            "exploitability of the weakness."
        ),
        expected_observation_template=(
            "Using synthetic authentication tokens on the designated test tenant "
            "{asset}, verify whether the auth-validation gap permits access to "
            "protected resources without valid credentials."
        ),
        proposed_method=(
            "Controlled authorization test using synthetic tokens on designated "
            "test tenant only. No real user accounts, no credential manipulation, "
            "fully isolated from production authentication systems."
        ),
        expected_evidence=[
            "Authentication bypass success/failure log",
            "Scope of accessible resources without valid credentials",
            "No impact on production authentication systems",
        ],
        risk_level="high",
        scope_impact="expands_understanding",
        authorization_impact="requires_test_tenant_auth",
        trust_boundary_impact="crosses_authentication_boundary",
        safe_test_available=True,
        safe_test_description=(
            "Synthetic token test on designated test tenant only — no real user "
            "accounts, fully isolated authentication context."
        ),
        title_template="Auth-validation test following {finding_title}",
    ),
    ChainingPattern(
        pattern_id="E",
        label="Exposed management surface → configuration-risk review",
        trigger_keywords=[
            "admin", "management", "console", "dashboard", "panel",
            "configuration", "exposed", "publicly accessible", "management interface",
            "control panel", "admin interface",
        ],
        trigger_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        rationale_template=(
            "An exposed management surface on {asset} presents configuration risk. "
            "This hypothesis proposes a read-only review of the exposed interface "
            "to assess the extent of configuration exposure without accessing or "
            "modifying any settings."
        ),
        expected_observation_template=(
            "Perform a read-only review of the exposed management surface on "
            "{asset} to catalog visible configuration details and assess whether "
            "sensitive configuration information is accessible."
        ),
        proposed_method=(
            "Read-only configuration review — observe visible surface only, "
            "no authentication attempt, no configuration changes, no secret "
            "extraction. Catalog only publicly visible information."
        ),
        expected_evidence=[
            "Catalog of visible configuration elements",
            "Assessment of sensitive-data exposure through management surface",
            "No authentication attempts, no configuration modifications",
        ],
        risk_level="medium",
        scope_impact="configuration_discovery",
        authorization_impact="none_if_read_only",
        trust_boundary_impact="may_indicate_internal_exposure",
        safe_test_available=True,
        safe_test_description=(
            "Read-only observation of publicly visible surface — no authentication, "
            "no configuration changes, no secret access."
        ),
        title_template="Configuration-risk review following {finding_title}",
    ),
    ChainingPattern(
        pattern_id="F",
        label="Missing rate controls → bounded resilience hypothesis",
        trigger_keywords=[
            "rate limit", "rate limiting", "throttle", "dos", "denial of service",
            "flood", "brute force", "unlimited", "no limit", "missing rate",
            "resilience", "resource exhaustion",
        ],
        trigger_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        rationale_template=(
            "Missing rate controls on {asset} may indicate broader resilience "
            "weaknesses. This hypothesis proposes a bounded, low-volume resilience "
            "test using synthetic credentials to assess the impact of controlled "
            "request patterns."
        ),
        expected_observation_template=(
            "Using low-volume, synthetic-credential request patterns on {asset}, "
            "observe response behavior and resource consumption to determine "
            "whether missing rate controls extend to other endpoints or resource "
            "classes."
        ),
        proposed_method=(
            "Bounded resilience test — low-volume requests with synthetic "
            "credentials only. Maximum 10 requests per minute. No resource "
            "exhaustion, no denial-of-service simulation."
        ),
        expected_evidence=[
            "Response time and status code patterns across controlled request window",
            "Identification of additional endpoints lacking rate controls",
            "No service degradation observed",
        ],
        risk_level="low",
        scope_impact="resilience_assessment",
        authorization_impact="requires_low_volume_synthetic",
        trust_boundary_impact="none",
        safe_test_available=True,
        safe_test_description=(
            "Low-volume bounded test — max 10 req/min, synthetic credentials only, "
            "no service degradation risk."
        ),
        title_template="Resilience-bound test following {finding_title}",
    ),
]


# ═══════════════════════════════════════════════════════════════
# Safety-gate helpers
# ═══════════════════════════════════════════════════════════════

TRUST_BOUNDARY_KEYWORDS: Dict[str, List[str]] = {
    "anonymous_to_authenticated": ["anonymous", "unauthenticated", "guest", "public access"],
    "user_to_other_user": ["user", "horizontal", "peer", "same role", "tenant isolation"],
    "user_to_administrator": ["admin", "administrator", "root", "superuser", "privilege escalation"],
    "public_to_internal": ["internal", "private", "intranet", "vpc", "corporate network"],
    "frontend_to_backend": ["frontend", "backend", "api", "server-side", "client-side"],
    "tenant_a_to_tenant_b": ["tenant", "multi-tenant", "cross-tenant", "isolation"],
    "external_to_internal": ["external", "internet", "dmz", "perimeter", "firewall"],
    "untrusted_to_trusted": ["untrusted", "sandbox", "isolated", "zero trust"],
}

RECON_BROAD_KEYWORDS: Set[str] = {
    "full scan", "port scan", "vulnerability scan", "recon", "enumerate all",
    "discover all", "crawl", "spider", "fuzz all", "brute force all",
    "full assessment", "complete scan", "full recon", "scan everything",
}


def _contains_broad_recon(text: str) -> bool:
    """Reject any hypothesis that suggests full/broad reconnaissance."""
    lower = text.lower()
    return any(kw in lower for kw in RECON_BROAD_KEYWORDS)


def _contains_prohibited_action(text: str) -> bool:
    """Reject hypotheses that propose active exploitation.

    Uses word-boundary matching so that 'exploitable' does not match
    the prohibited word 'exploit'. Multi-word phrases use substring
    matching since they are unlikely to have false positives.
    """
    lower = text.lower()
    # Single-word prohibited terms with word-boundary matching
    single_words = ["exploit", "exploitation", "pivot", "payload"]
    for word in single_words:
        pattern = r'(?<![a-z])' + re.escape(word) + r'(?![a-z])'
        if re.search(pattern, lower):
            return True
    # Multi-word phrases — use substring matching (rare enough to
    # not cause false positives)
    multi_word = ["lateral movement"]
    for phrase in multi_word:
        if phrase in lower:
            return True
    return False


def _matches_trust_boundary(text: str) -> List[str]:
    """Return trust-boundary categories that match the given text."""
    lower = text.lower()
    matched = []
    for category, keywords in TRUST_BOUNDARY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            matched.append(category)
    return matched


def _evaluate_safety_gates(
    hypothesis_data: Dict[str, Any],
    finding: FindingNode,
    authorization: Dict[str, Any],
    mission_scope: Dict[str, Any],
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Evaluate all safety gates for a proposed hypothesis.

    Returns (is_safe, blocker_reason, modified_status).
    """
    # Gate 1: No broad reconnaissance
    combined_text = " ".join([
        hypothesis_data.get("rationale", ""),
        hypothesis_data.get("proposed_method", ""),
        hypothesis_data.get("expected_observation", ""),
    ])
    if _contains_broad_recon(combined_text):
        return False, "Hypothesis proposes broad reconnaissance or scanning — rejected.", "REJECTED"

    # Gate 2: Authorization check
    auth_impact = hypothesis_data.get("authorization_impact", "none")
    if auth_impact == "requires_test_tenant_auth":
        # Check if mission has test-tenant authorization
        authorized_assets = authorization.get("authorized_assets", [])
        if hypothesis_data["target_asset"] not in authorized_assets:
            return False, (
                f"Target asset '{hypothesis_data['target_asset']}' not in authorized scope. "
                f"Requires additional authorization."
            ), "BLOCKED_BY_AUTHORIZATION"

    # Gate 3: Scope check
    scope_assets = mission_scope.get("in_scope_assets", [])
    scope_methods = mission_scope.get("allowed_methods", [])
    if scope_assets and hypothesis_data["target_asset"] not in scope_assets:
        return False, (
            f"Target asset '{hypothesis_data['target_asset']}' is out of mission scope."
        ), "BLOCKED_BY_SCOPE"

    # Gate 4: No exploitation of production
    if _contains_prohibited_action(combined_text):
        return False, "Hypothesis proposes active exploitation — rejected by safety gate.", "REJECTED"

    # Gate 5: Evidence-linked — must reference at least one parent finding
    if not hypothesis_data.get("parent_finding_ids"):
        return False, "Hypothesis has no parent findings — must be evidence-linked.", "REJECTED"

    return True, None, None


# ═══════════════════════════════════════════════════════════════
# FindingChainPlanner
# ═══════════════════════════════════════════════════════════════

class FindingChainPlanner:
    """Generates bounded, evidence-linked chain hypotheses from validated findings.

    The planner analyzes a validated finding against the mission scope and
    current authorization state, then proposes one or more bounded hypotheses
    following the approved chaining patterns A–F. Every hypothesis is
    evidence-linked (references the parent finding) and evaluated against
    safety gates before emission.

    Usage::

        planner = FindingChainPlanner()
        hypotheses = planner.generate_hypotheses(
            finding=finding_node,
            graph=findings_graph,
            mission_scope={"in_scope_assets": [...], "allowed_methods": [...]},
            authorization={"authorized_assets": [...], "role": "..."},
        )
    """

    def __init__(self) -> None:
        self._patterns: List[ChainingPattern] = list(APPROVED_PATTERNS)
        self._generated_count: int = 0
        self._blocked_count: int = 0

    # ── Public API ──────────────────────────────────────────────

    def generate_hypotheses(
        self,
        finding: FindingNode,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
    ) -> List[ChainHypothesis]:
        """Generate bounded chain hypotheses from a validated finding.

        Parameters
        ----------
        finding:
            The validated finding to generate hypotheses from. Must be a
            validated node (validation_status == "VALIDATED" or the planner
            will still attempt generation but may produce lower-confidence
            hypotheses).
        graph:
            The current FindingsGraph containing all nodes, edges, and
            existing hypotheses. Used to avoid duplicates and to enrich
            hypotheses with contextual information.
        mission_scope:
            Dict with keys such as 'in_scope_assets', 'allowed_methods',
            'excluded_assets', 'mission_id'.
        authorization:
            Dict with keys such as 'authorized_assets', 'role',
            'authorization_level', 'restrictions'.

        Returns
        -------
        list[ChainHypothesis]
            Generated hypotheses that passed safety gates. Hypotheses that
            fail gates are logged but not returned.
        """
        hypotheses: List[ChainHypothesis] = []

        # Validate input preconditions
        if not finding or not finding.title:
            return hypotheses

        # Step 1: Identify which approved patterns match this finding
        matched_patterns = self._match_patterns(finding)

        # Step 2: For each matched pattern, generate a candidate hypothesis
        for pattern in matched_patterns:
            candidate = self._build_hypothesis(finding, pattern, graph, mission_scope, authorization)

            # Step 3: Evaluate safety gates
            candidate_data = candidate_to_dict(candidate)
            is_safe, blocker_reason, modified_status = _evaluate_safety_gates(
                candidate_data, finding, authorization, mission_scope
            )

            if not is_safe and modified_status:
                candidate.status = modified_status
                self._blocked_count += 1
                # Still return blocked hypotheses so the prioritizer can
                # surface them as BLOCKED_BY_AUTHORIZATION / BLOCKED_BY_SCOPE.
                hypotheses.append(candidate)
            elif is_safe:
                self._generated_count += 1
                hypotheses.append(candidate)
            # If is_safe is False and no modified_status, drop silently.

        # Step 3: Deduplicate — avoid hypotheses that already exist in graph
        existing_titles = {
            h.title for h in graph._hypotheses.values()
        }
        hypotheses = [h for h in hypotheses if h.title not in existing_titles]

        return hypotheses

    # ── Pattern matching ────────────────────────────────────────

    def _match_patterns(self, finding: FindingNode) -> List[ChainingPattern]:
        """Match the finding against approved chaining patterns.

        Matching is based on keyword overlap between the finding's title,
        description, observed_fact, and inferred_meaning against each
        pattern's trigger_keywords, plus node-type matching.
        """
        finding_text = " ".join(
            filter(None, [
                finding.title,
                finding.description,
                finding.observed_fact,
                finding.inferred_meaning or "",
            ])
        ).lower()

        matched: List[ChainingPattern] = []
        for pattern in self._patterns:
            # Node-type filter
            if finding.node_type not in pattern.trigger_node_types:
                continue

            # Keyword match
            keyword_hits = sum(
                1 for kw in pattern.trigger_keywords
                if kw.lower() in finding_text
            )
            if keyword_hits > 0:
                matched.append(pattern)

        # If no pattern matched, try a fallback: use the broadest pattern
        # (pattern D) for any FINDING/ACCESS_CONDITION, or pattern C for
        # OBSERVATIONs — but only if it passes keyword matching.
        if not matched:
            matched = self._fallback_match(finding)

        return matched

    def _fallback_match(self, finding: FindingNode) -> List[ChainingPattern]:
        """Fallback matching when no pattern keywords match directly.

        Uses broader heuristics: severity, materiality, affected trust
        boundaries, and existing graph context.
        """
        # High-severity findings with trust-boundary impact → pattern D
        if finding.severity in ("critical", "high") and finding.affected_trust_boundaries:
            return [p for p in self._patterns if p.pattern_id == "D"]

        # Findings on management surfaces → pattern E
        title_lower = (finding.title + " " + finding.description).lower()
        if any(kw in title_lower for kw in ["admin", "management", "console", "dashboard"]):
            return [p for p in self._patterns if p.pattern_id == "E"]

        # Observations about errors → pattern C
        if finding.node_type == FindingNodeType.OBSERVATION and (
            "error" in title_lower or "exception" in title_lower
        ):
            return [p for p in self._patterns if p.pattern_id == "C"]

        # Generic finding with access-control implications → pattern B
        if finding.node_type in (FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION):
            return [p for p in self._patterns if p.pattern_id == "B"]

        # Last-resort fallback: pattern C (safest, lowest risk)
        return [p for p in self._patterns if p.pattern_id == "C"]

    # ── Hypothesis construction ─────────────────────────────────

    def _build_hypothesis(
        self,
        finding: FindingNode,
        pattern: ChainingPattern,
        graph: FindingsGraph,
        mission_scope: Dict[str, Any],
        authorization: Dict[str, Any],
    ) -> ChainHypothesis:
        """Build a fully-formed ChainHypothesis from a finding and pattern."""

        # Determine target asset
        target_asset = self._resolve_target_asset(finding, pattern, graph)

        # Build title
        title = pattern.title_template.format(
            finding_title=finding.title,
            asset=target_asset,
        )

        # Build rationale
        rationale = pattern.rationale_template.format(
            asset=target_asset,
            finding_title=finding.title,
        )

        # Build expected observation
        expected_observation = pattern.expected_observation_template.format(
            asset=target_asset,
            finding_title=finding.title,
        )

        # Build the hypothesis
        hypothesis = ChainHypothesis.create(
            mission_id=finding.mission_id or mission_scope.get("mission_id", ""),
            parent_finding_ids=[finding.node_id],
            title=title,
            rationale=rationale,
            expected_observation=expected_observation,
            target_asset=target_asset,
            proposed_method=pattern.proposed_method,
            expected_evidence=list(pattern.expected_evidence),
            risk_level=pattern.risk_level,
            scope_impact=pattern.scope_impact,
            authorization_impact=pattern.authorization_impact,
            trust_boundary_impact=pattern.trust_boundary_impact,
            safe_test_available=pattern.safe_test_available,
            safe_test_description=pattern.safe_test_description,
            proposed_by="CHAIN_PLANNER",
            status=HypothesisStatus.PROPOSED.value,
        )

        # If a safe test is available, upgrade status
        if pattern.safe_test_available:
            hypothesis.status = HypothesisStatus.SAFE_VALIDATION_AVAILABLE.value

        # Check for authorization impact
        if pattern.authorization_impact in (
            "requires_test_tenant_auth",
            "requires_additional_authorization",
        ):
            if authorization.get("authorization_level", "") == "FULL":
                # Already fully authorized
                hypothesis.authorization_impact = "covered"
            else:
                hypothesis.status = HypothesisStatus.REQUIRES_ADDITIONAL_AUTHORIZATION.value

        return hypothesis

    def _resolve_target_asset(
        self,
        finding: FindingNode,
        pattern: ChainingPattern,
        graph: FindingsGraph,
    ) -> str:
        """Determine the best target asset for the hypothesis.

        Priority: finding's primary affected asset → related nodes in graph
        → first affected asset from finding.affected_assets.
        """
        if finding.affected_assets:
            return finding.affected_assets[0]

        # Look at connected nodes in the graph for asset hints
        edges = graph.get_edges_for_node(finding.node_id)
        for edge in edges:
            target_node = graph.get_node(edge.target_node_id)
            if target_node and target_node.affected_assets:
                return target_node.affected_assets[0]

        # Fallback: use finding node ID as a synthetic asset identifier
        return f"asset-related-to-{finding.node_id[:8]}"

    # ── Introspection ───────────────────────────────────────────

    @property
    def generated_count(self) -> int:
        """Number of safe hypotheses generated in this planner session."""
        return self._generated_count

    @property
    def blocked_count(self) -> int:
        """Number of hypotheses blocked by safety gates in this session."""
        return self._blocked_count

    @property
    def pattern_count(self) -> int:
        """Number of loaded chaining patterns."""
        return len(self._patterns)


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def candidate_to_dict(h: ChainHypothesis) -> Dict[str, Any]:
    """Convert a ChainHypothesis to a plain dict for safety-gate evaluation."""
    return {
        "title": h.title,
        "rationale": h.rationale,
        "expected_observation": h.expected_observation,
        "target_asset": h.target_asset,
        "proposed_method": h.proposed_method,
        "expected_evidence": h.expected_evidence,
        "risk_level": h.risk_level,
        "scope_impact": h.scope_impact,
        "authorization_impact": h.authorization_impact,
        "trust_boundary_impact": h.trust_boundary_impact,
        "safe_test_available": h.safe_test_available,
        "safe_test_description": h.safe_test_description,
        "parent_finding_ids": h.parent_finding_ids,
    }
