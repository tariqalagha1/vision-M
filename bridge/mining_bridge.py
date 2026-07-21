"""
vision-M Bridge: Mining
========================
Connects Atlas MiningWorker → H-Scraper business intelligence & extraction engines.

Architecture:
  Layer 1 (orchestration): MiningWorker dispatches analysis job
  Bridge: MiningBridge routes to intelligence engines
  Layer 2 (execution): BusinessIntelligence, EvidenceIntelligence, Temporal analysis
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

# ── H-Scraper paths ──────────────────────────────────────────────
_HSCRAPER_BACKEND = Path("/data/workspace/H-scraper-/backend")
_HSCRAPER_ROOT = Path("/data/workspace/H-scraper-")
for p in [_HSCRAPER_BACKEND, _HSCRAPER_ROOT]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


class MiningBridge:
    """Bridges Atlas orchestration to H-Scraper intelligence engines."""

    def __init__(self):
        self._available = None

    @property
    def available(self) -> bool:
        if self._available is None:
            try:
                from hscraper.enterprise.business_intelligence.service import BusinessIntelligenceService
                self._available = True
            except ImportError:
                try:
                    from app.services.extraction_fallback_engine import ExtractionFallbackEngine
                    self._available = True
                except ImportError:
                    self._available = False
        return self._available

    # ── Data Sufficiency ──────────────────────────────────────────

    def assess_sufficiency(self, data: list, source: str) -> Dict[str, Any]:
        """Assess whether data volume and quality are sufficient for mining."""
        record_count = len(data) if isinstance(data, list) else 0
        fields = set()
        if data and isinstance(data, list) and isinstance(data[0], dict):
            fields = set(data[0].keys())

        sufficiency = "INSUFFICIENT"
        if record_count >= 100:
            sufficiency = "SUFFICIENT"
        elif record_count >= 10:
            sufficiency = "MARGINAL"
        elif record_count > 0:
            sufficiency = "LOW"

        return {
            "status": sufficiency,
            "record_count": record_count,
            "available_fields": sorted(fields) if fields else [],
            "field_count": len(fields),
            "recommendation": (
                "Data volume sufficient for statistical analysis" if sufficiency == "SUFFICIENT"
                else "Increase sample size for reliable patterns" if sufficiency == "MARGINAL"
                else "Insufficient data for mining — acquire more records"
            ),
        }

    # ── Baseline Establishment ─────────────────────────────────────

    def establish_baseline(self, data: list) -> Dict[str, Any]:
        """Establish statistical baseline from data sample."""
        record_count = len(data) if isinstance(data, list) else 0

        metrics = {
            "record_count": record_count,
            "numeric_fields": 0,
            "text_fields": 0,
            "temporal_fields": 0,
        }

        if data and isinstance(data, list) and isinstance(data[0], dict):
            sample = data[0]
            for key, val in sample.items():
                if isinstance(val, (int, float)):
                    metrics["numeric_fields"] += 1
                elif isinstance(val, str):
                    if any(t in key.lower() for t in ["date", "time", "created", "updated", "timestamp"]):
                        metrics["temporal_fields"] += 1
                    else:
                        metrics["text_fields"] += 1

        return {
            "status": "established",
            "metrics": metrics,
            "confidence": 0.7 if record_count >= 10 else 0.4,
        }

    # ── Pattern Discovery ──────────────────────────────────────────

    def discover_patterns(self, data: list, fields: Optional[list] = None) -> Dict[str, Any]:
        """Discover patterns using H-Scraper business intelligence."""
        patterns = []

        try:
            from hscraper.enterprise.business_intelligence.service import BusinessIntelligenceService
            bi = BusinessIntelligenceService()

            if data and len(data) >= 5 and isinstance(data[0], dict):
                target_fields = fields or list(data[0].keys())[:5]

                for field in target_fields:
                    values = [str(r.get(field, "")) for r in data if field in r]
                    unique = len(set(values))
                    total = len(values)

                    if total > 0:
                        uniqueness = unique / total
                        if uniqueness > 0.8:
                            patterns.append({
                                "field": field,
                                "pattern_type": "HIGH_CARDINALITY",
                                "uniqueness_ratio": round(uniqueness, 2),
                                "unique_values": unique,
                                "total_values": total,
                            })
                        elif uniqueness < 0.2:
                            top_value = max(set(values), key=values.count)
                            patterns.append({
                                "field": field,
                                "pattern_type": "LOW_CARDINALITY",
                                "uniqueness_ratio": round(uniqueness, 2),
                                "dominant_value": top_value,
                                "dominant_count": values.count(top_value),
                            })

            # Add BI insights if available
            if hasattr(bi, 'analyze_trends'):
                try:
                    bi_insights = bi.analyze_trends(data[:100])
                    patterns.append({"pattern_type": "BI_INSIGHT", "data": str(bi_insights)[:500]})
                except Exception:
                    pass

        except ImportError:
            # Fallback: basic statistical pattern detection
            if data and isinstance(data, list) and isinstance(data[0], dict):
                for field in list(data[0].keys())[:5]:
                    values = [str(r.get(field, "")) for r in data if field in r]
                    if values:
                        patterns.append({
                            "field": field,
                            "pattern_type": "BASIC_STATS",
                            "unique_values": len(set(values)),
                            "total_values": len(values),
                        })

        return {
            "status": "completed",
            "patterns_detected": len(patterns),
            "patterns": patterns[:10],
        }

    # ── Trend Analysis ─────────────────────────────────────────────

    def analyze_trends(self, data: list) -> Dict[str, Any]:
        """Analyze temporal trends using H-Scraper temporal intelligence."""
        try:
            from hscraper.intelligence.temporal.service import TemporalIntelligenceService
            temporal = TemporalIntelligenceService()

            if hasattr(temporal, 'analyze'):
                trends = temporal.analyze(data[:200] if len(data) > 200 else data)
                return {
                    "status": "completed",
                    "engine": "TemporalIntelligenceService",
                    "trends": str(trends)[:1000],
                }
        except ImportError:
            pass

        # Fallback: count-based trend estimation
        return {
            "status": "completed",
            "engine": "basic_stats",
            "record_count": len(data) if isinstance(data, list) else 0,
            "trend": "stable" if len(data) > 0 else "no_data",
        }

    # ── Insight Synthesis ──────────────────────────────────────────

    def synthesize_insights(self, patterns: list, trends: dict,
                            source: str) -> Dict[str, Any]:
        """Synthesize commercial intelligence from mining results."""
        insights = []

        if patterns:
            insights.append(f"Discovered {len(patterns)} patterns across source: {source}")

        high_card = [p for p in patterns if p.get("pattern_type") in
                     ("HIGH_CARDINALITY", "BI_INSIGHT")]
        if high_card:
            insights.append(f"{len(high_card)} high-value patterns warrant further investigation")

        return {
            "status": "synthesized",
            "insight_count": len(insights),
            "insights": insights,
            "commercial_value": "HIGH" if len(high_card) >= 2 else "MEDIUM" if high_card else "LOW",
        }

    # ── Validation ─────────────────────────────────────────────────

    def validate_findings(self, patterns: list, insights: dict) -> Dict[str, Any]:
        """Cross-reference and validate mining findings."""
        issues = []

        if not patterns:
            issues.append("No patterns detected — validation inconclusive")

        if insights.get("commercial_value") == "LOW":
            issues.append("Low commercial value — insufficient signal")

        return {
            "status": "validated" if not issues else "partial",
            "issues": issues,
            "confidence": 0.8 if not issues else 0.5,
        }


# ── Singleton ─────────────────────────────────────────────────────
_mining_bridge: Optional[MiningBridge] = None


def get_mining_bridge() -> MiningBridge:
    global _mining_bridge
    if _mining_bridge is None:
        _mining_bridge = MiningBridge()
    return _mining_bridge
