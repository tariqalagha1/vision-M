"""
ATLAS PHASE 1 — Routing Matrix
================================
Resolves (source_engine, finding_type, attributes) → (target_engine, action_type, params).
Supports all 9 directions. No keyword substring matching in the primary path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .dispatch_contract import TargetEngine
from .finding_node import FindingNode, FindingNodeType


# ═══════════════════════════════════════════════════════════════
# Routing rule
# ═══════════════════════════════════════════════════════════════

@dataclass
class RoutingRule:
    """A single routing rule: source engine + finding type → target engine + action."""

    rule_id: str
    source_engine: str
    target_engine: str
    finding_node_types: List[FindingNodeType]  # Which node types trigger this rule
    action_type: str
    action_label: str
    required_params: List[str] = field(default_factory=list)
    auth_requirements: List[str] = field(default_factory=list)
    priority: int = 50  # lower = higher priority

    def matches(self, finding: FindingNode, source_engine: str) -> bool:
        """Check if this rule matches the given finding and source engine."""
        if source_engine != self.source_engine:
            return False
        if finding.node_type not in self.finding_node_types:
            return False
        return True


# ═══════════════════════════════════════════════════════════════
# 9-Direction routing rules
# ═══════════════════════════════════════════════════════════════

NINE_DIRECTION_RULES: List[RoutingRule] = [
    # ── Cross-engine ──────────────────────────────────────────

    # SCRAPING → MINING: scraping finds a data source → mine it
    RoutingRule(
        rule_id="SCRAPE_TO_MINE",
        source_engine=TargetEngine.SCRAPING.value,
        target_engine=TargetEngine.MINING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        action_type="mine_discovered_source",
        action_label="Mine data from scraped source",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=10,
    ),

    # SCRAPING → SECURITY: scraping finds endpoint → security assess
    RoutingRule(
        rule_id="SCRAPE_TO_SEC",
        source_engine=TargetEngine.SCRAPING.value,
        target_engine=TargetEngine.SECURITY.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION],
        action_type="assess_discovered_endpoint",
        action_label="Security assessment of scraped endpoint",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["test_tenant_auth"],
        priority=10,
    ),

    # MINING → SCRAPING: mining finds data gap → re-scrape
    RoutingRule(
        rule_id="MINE_TO_SCRAPE",
        source_engine=TargetEngine.MINING.value,
        target_engine=TargetEngine.SCRAPING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.DATA_SOURCE],
        action_type="rescrape_for_mining",
        action_label="Re-scrape source for mining gap fill",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=10,
    ),

    # MINING → SECURITY: mining finds anomaly → security investigate
    RoutingRule(
        rule_id="MINE_TO_SEC",
        source_engine=TargetEngine.MINING.value,
        target_engine=TargetEngine.SECURITY.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.TRUST_BOUNDARY],
        action_type="investigate_mining_anomaly",
        action_label="Security investigation of mining anomaly",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["test_tenant_auth"],
        priority=10,
    ),

    # SECURITY → SCRAPING: security finds new surface → scrape it
    RoutingRule(
        rule_id="SEC_TO_SCRAPE",
        source_engine=TargetEngine.SECURITY.value,
        target_engine=TargetEngine.SCRAPING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        action_type="scrape_security_finding",
        action_label="Scrape surfaced by security finding",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=10,
    ),

    # SECURITY → MINING: security finds data exposure → mine for scope
    RoutingRule(
        rule_id="SEC_TO_MINE",
        source_engine=TargetEngine.SECURITY.value,
        target_engine=TargetEngine.MINING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION],
        action_type="mine_exposed_data",
        action_label="Mine data exposed by security finding",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=10,
    ),

    # ── Same-engine ──────────────────────────────────────────

    # SCRAPING → SCRAPING: deeper scraping of same/related asset
    RoutingRule(
        rule_id="SCRAPE_TO_SCRAPE",
        source_engine=TargetEngine.SCRAPING.value,
        target_engine=TargetEngine.SCRAPING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.OBSERVATION],
        action_type="deep_scrape_related",
        action_label="Deeper scrape of related asset",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=20,
    ),

    # MINING → MINING: deeper mining on related dataset
    RoutingRule(
        rule_id="MINE_TO_MINE",
        source_engine=TargetEngine.MINING.value,
        target_engine=TargetEngine.MINING.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.DATA_SOURCE],
        action_type="deep_mine_related",
        action_label="Deeper mining on related dataset",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["scope_verification"],
        priority=20,
    ),

    # SECURITY → SECURITY: deeper security assessment
    RoutingRule(
        rule_id="SEC_TO_SEC",
        source_engine=TargetEngine.SECURITY.value,
        target_engine=TargetEngine.SECURITY.value,
        finding_node_types=[FindingNodeType.FINDING, FindingNodeType.ACCESS_CONDITION,
                            FindingNodeType.TRUST_BOUNDARY],
        action_type="deep_assess_related",
        action_label="Deeper security assessment of related target",
        required_params=["target_asset", "evidence_ids"],
        auth_requirements=["test_tenant_auth"],
        priority=20,
    ),
]


# ═══════════════════════════════════════════════════════════════
# Routing resolver
# ═══════════════════════════════════════════════════════════════

class RoutingResolver:
    """Resolves routing rules for a given finding and source engine."""

    def __init__(self, rules: Optional[List[RoutingRule]] = None):
        self._rules = rules or list(NINE_DIRECTION_RULES)
        # Sort by priority (lower = higher)
        self._rules.sort(key=lambda r: r.priority)

    def resolve(
        self,
        finding: FindingNode,
        source_engine: str,
        preferred_target: Optional[str] = None,
    ) -> Optional[RoutingRule]:
        """Find the best matching routing rule.

        Args:
            finding: The source finding to route from.
            source_engine: The engine that produced the finding.
            preferred_target: Optional preferred target engine override.

        Returns:
            The best matching RoutingRule, or None if no rule matches.
        """
        candidates = [r for r in self._rules if r.matches(finding, source_engine)]

        if not candidates:
            return None

        # If a preferred target is specified, prefer rules matching it
        if preferred_target:
            preferred = [r for r in candidates if r.target_engine == preferred_target]
            if preferred:
                candidates = preferred

        # Return highest-priority (lowest number) match
        return candidates[0]

    def add_rule(self, rule: RoutingRule) -> None:
        """Add a custom routing rule."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    @property
    def rule_count(self) -> int:
        return len(self._rules)
