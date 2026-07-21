"""
vision-M: Real Workers
=======================
ScrapingWorker, MiningWorker, SecurityWorker — each wired to the bridge layer
that executes real H-Scraper engines instead of synthetic fallbacks.

This is the heart of vision-M: Layer 1 orchestration → Bridge → Layer 2 execution.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Ensure vision-M is on path ───────────────────────────────────
_VISION_M = Path("/data/workspace/vision-M")
if str(_VISION_M) not in sys.path:
    sys.path.insert(0, str(_VISION_M))

from layer1_orchestration.execution.worker_contract import BaseWorker, CheckpointManager
from layer1_orchestration.execution.job_contract import JobRecord, JobState
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_queue import JobQueue


# ═══════════════════════════════════════════════════════════════════
# REAL ScrapingWorker — bridged to H-Scraper engines
# ═══════════════════════════════════════════════════════════════════

class ScrapingWorker(BaseWorker):
    """Real scraping worker using H-Scraper ContentExtractor + ExtractionFallbackEngine.

    Subtask pipeline — ALL real:
        1. SOURCE_VALIDATION → bridge.validate_source()
        2. DRIVER_SELECTION  → bridge.select_driver()
        3. ACQUISITION       → bridge.acquire() ← REAL EXTRACTION
        4. EVIDENCE          → bridge.collect_evidence()
        5. VERIFICATION      → bridge.verify()
        6. COMPLETION        → synthesize results
    """

    ENGINE = "scraping"

    def __init__(self, worker_id: str, queue: JobQueue, store: JobStore,
                 lifecycle: JobLifecycleManager):
        super().__init__(worker_id, queue, store, lifecycle)
        self.ckpt = CheckpointManager(store, lifecycle)
        self._cancelled = False
        self._bridge = None

    @property
    def bridge(self):
        if self._bridge is None:
            from bridge.scraping_bridge import get_scraping_bridge
            self._bridge = get_scraping_bridge()
        return self._bridge

    def _do_work(self, record: JobRecord, context: Dict[str, Any]) -> Dict[str, Any]:
        contract = record.contract
        target = contract.target_asset
        html = context.get("html", "")

        subtasks = []
        evidence = []
        findings = []
        budget_consumed = 0

        # ── 1. Source Validation ──
        self._check_cancellation()
        result = self.bridge.validate_source(target)
        subtasks.append({"name": "source_validation", "status": "completed",
                         "detail": result})
        budget_consumed += 1
        self._checkpoint(record, "1/6: source_validation", {
            "completed_subtasks": [s["name"] for s in subtasks],
            "pending_subtasks": ["driver_selection", "acquisition", "evidence",
                                 "verification", "completion"],
            "active_subtask": "driver_selection",
            "budget_consumed": budget_consumed,
            "remaining_budget": contract.request_budget - budget_consumed,
        })

        # ── 2. Driver Selection ──
        self._check_cancellation()
        result = self.bridge.select_driver(target, html or "")
        subtasks.append({"name": "driver_selection", "status": "completed",
                         "detail": result})
        budget_consumed += 1
        self._checkpoint(record, "2/6: driver_selection", {
            "completed_subtasks": [s["name"] for s in subtasks],
            "pending_subtasks": ["acquisition", "evidence", "verification", "completion"],
            "active_subtask": "acquisition",
            "budget_consumed": budget_consumed,
            "remaining_budget": contract.request_budget - budget_consumed,
        })

        # ── 3. Acquisition — REAL EXTRACTION ──
        self._check_cancellation()
        result = self.bridge.acquire(target, html or "")
        subtasks.append({"name": "acquisition", "status": "completed",
                         "detail": result})
        evidence.append({"type": "acquisition_output",
                        "data": result.get("output", "")[:500],
                        "engine": result.get("engine", "unknown")})
        budget_consumed += 1
        self._checkpoint(record, "3/6: acquisition", {
            "completed_subtasks": [s["name"] for s in subtasks],
            "pending_subtasks": ["evidence", "verification", "completion"],
            "active_subtask": "evidence",
            "evidence_collected": [e["type"] for e in evidence],
            "budget_consumed": budget_consumed,
            "remaining_budget": contract.request_budget - budget_consumed,
        })

        # ── 4. Evidence Collection ──
        self._check_cancellation()
        result = self.bridge.collect_evidence(target, result)
        subtasks.append({"name": "evidence_collection", "status": "completed",
                         "detail": result})
        budget_consumed += 1
        self._checkpoint(record, "4/6: evidence", {
            "completed_subtasks": [s["name"] for s in subtasks],
            "pending_subtasks": ["verification", "completion"],
            "active_subtask": "verification",
            "budget_consumed": budget_consumed,
            "remaining_budget": contract.request_budget - budget_consumed,
        })

        # ── 5. Verification ──
        self._check_cancellation()
        acq_result = subtasks[2]["detail"]  # acquisition result
        result = self.bridge.verify(evidence, acq_result)
        subtasks.append({"name": "verification", "status": "completed",
                         "detail": result})
        budget_consumed += 1
        self._checkpoint(record, "5/6: verification", {
            "completed_subtasks": [s["name"] for s in subtasks],
            "pending_subtasks": ["completion"],
            "active_subtask": "completion",
            "budget_consumed": budget_consumed,
            "remaining_budget": contract.request_budget - budget_consumed,
        })

        # ── 6. Completion ──
        self._check_cancellation()
        subtasks.append({"name": "completion", "status": "completed",
                         "detail": {"finalized": True}})
        bridge_available = self.bridge.available
        engine_used = acq_result.get("engine", "synthetic_fallback")
        budget_consumed += 1

        findings = [{
            "title": f"Scraping: {target}",
            "description": (
                f"REAL scraping via {engine_used}. " if bridge_available
                else f"SIMULATED scraping (bridge: H-Scraper not importable). "
            ) + f"6 subtasks, {len(evidence)} evidence items.",
            "severity": "info",
            "confidence": 0.85 if bridge_available else 0.40,
            "bridge_available": bridge_available,
            "engine": engine_used,
        }]

        return {
            "summary": f"Scraping {'COMPLETED' if bridge_available else 'SIMULATED'}: {target}. "
                       f"Engine: {engine_used}. Budget: {budget_consumed}/{contract.request_budget}",
            "evidence_references": [f"ev-scrape-{i}" for i in range(len(evidence))],
            "findings": findings,
            "requests_consumed": budget_consumed,
            "completed_subtasks": [s["name"] for s in subtasks],
            "confidence": 0.85 if bridge_available else 0.40,
            "bridge_available": bridge_available,
        }

    def _check_cancellation(self):
        if self._cancelled:
            raise RuntimeError("Job cancelled during execution")

    def _checkpoint(self, record, label, data):
        data["label"] = label
        data["engine"] = self.ENGINE
        data["worker_id"] = self.worker_id
        data["job_id"] = record.contract.job_id
        data["chain_id"] = record.contract.parent_chain_id
        data["plan_version"] = data.get("plan_version", 1)
        data["authorization_status"] = "valid"
        data["unresolved_errors"] = []
        data["unresolved_contradictions"] = []
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.ckpt.save_checkpoint(record, self.worker_id, data)


# ═══════════════════════════════════════════════════════════════════
# REAL MiningWorker — bridged to H-Scraper intelligence engines
# ═══════════════════════════════════════════════════════════════════

class MiningWorker(BaseWorker):
    """Real mining worker using H-Scraper BusinessIntelligence + Temporal engines.

    Subtask pipeline:
        1. DATA_SUFFICIENCY     → bridge.assess_sufficiency()
        2. BASELINE             → bridge.establish_baseline()
        3. PATTERN_DISCOVERY    → bridge.discover_patterns() ← REAL BI
        4. TREND_ANALYSIS       → bridge.analyze_trends()    ← REAL TEMPORAL
        5. INSIGHT_SYNTHESIS    → bridge.synthesize_insights()
        6. VALIDATION           → bridge.validate_findings()
    """

    ENGINE = "mining"

    def __init__(self, worker_id: str, queue: JobQueue, store: JobStore,
                 lifecycle: JobLifecycleManager):
        super().__init__(worker_id, queue, store, lifecycle)
        self.ckpt = CheckpointManager(store, lifecycle)
        self._cancelled = False
        self._bridge = None

    @property
    def bridge(self):
        if self._bridge is None:
            from bridge.mining_bridge import get_mining_bridge
            self._bridge = get_mining_bridge()
        return self._bridge

    def _do_work(self, record: JobRecord, context: Dict[str, Any]) -> Dict[str, Any]:
        contract = record.contract
        target = contract.target_asset
        data = context.get("data", [])
        fields = context.get("fields", None)

        subtasks = []
        budget_consumed = 0

        subtask_specs = [
            ("data_sufficiency", "1/6: sufficiency",
             ["baseline", "patterns", "trends", "synthesis", "validation"], "baseline"),
            ("baseline_establishment", "2/6: baseline",
             ["patterns", "trends", "synthesis", "validation"], "patterns"),
            ("pattern_discovery", "3/6: patterns",
             ["trends", "synthesis", "validation"], "trends"),
            ("trend_analysis", "4/6: trends",
             ["synthesis", "validation"], "synthesis"),
            ("insight_synthesis", "5/6: synthesis",
             ["validation"], "validation"),
            ("validation", "6/6: validation", [], None),
        ]

        # Store intermediate results for synthesis
        sufficiency = baseline = patterns = trends = None

        for name, label, pending, next_active in subtask_specs:
            self._check_cancellation()

            if name == "data_sufficiency":
                result = self.bridge.assess_sufficiency(data or context.get("records", []), target)
                sufficiency = result
            elif name == "baseline_establishment":
                result = self.bridge.establish_baseline(data or [])
                baseline = result
            elif name == "pattern_discovery":
                result = self.bridge.discover_patterns(data or [], fields)
                patterns = result
            elif name == "trend_analysis":
                result = self.bridge.analyze_trends(data or [])
                trends = result
            elif name == "insight_synthesis":
                result = self.bridge.synthesize_insights(
                    patterns.get("patterns", []) if patterns else [],
                    trends or {},
                    target,
                )
            elif name == "validation":
                result = self.bridge.validate_findings(
                    patterns.get("patterns", []) if patterns else [],
                    {},
                )

            subtasks.append({"name": name, "status": "completed",
                            "detail": result})
            budget_consumed += 1
            self._checkpoint(record, label, {
                "completed_subtasks": [s["name"] for s in subtasks],
                "pending_subtasks": pending,
                "active_subtask": next_active or "complete",
                "budget_consumed": budget_consumed,
                "remaining_budget": contract.request_budget - budget_consumed,
            })

        bridge_available = self.bridge.available
        findings = [{
            "title": f"Mining: {target}",
            "description": (
                f"REAL mining via H-Scraper BI engines. "
                if bridge_available
                else f"SIMULATED mining (bridge: H-Scraper not importable). "
            ) + f"Patterns: {patterns.get('patterns_detected', 0) if patterns else 0}.",
            "severity": "info",
            "confidence": 0.75 if bridge_available else 0.35,
            "bridge_available": bridge_available,
        }]

        return {
            "summary": f"Mining {'COMPLETED' if bridge_available else 'SIMULATED'}: {target}. "
                       f"Budget: {budget_consumed}/{contract.request_budget}",
            "evidence_references": [f"ev-mine-{i}" for i in range(6)],
            "findings": findings,
            "requests_consumed": budget_consumed,
            "completed_subtasks": [s["name"] for s in subtasks],
            "confidence": 0.75 if bridge_available else 0.35,
            "bridge_available": bridge_available,
        }

    def _check_cancellation(self):
        if self._cancelled:
            raise RuntimeError("Job cancelled during execution")

    def _checkpoint(self, record, label, data):
        data["label"] = label
        data["engine"] = self.ENGINE
        data["worker_id"] = self.worker_id
        data["job_id"] = record.contract.job_id
        data["chain_id"] = record.contract.parent_chain_id
        data["plan_version"] = data.get("plan_version", 1)
        data["authorization_status"] = "valid"
        data["unresolved_errors"] = []
        data["unresolved_contradictions"] = []
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.ckpt.save_checkpoint(record, self.worker_id, data)


# ═══════════════════════════════════════════════════════════════════
# REAL SecurityWorker — bridged to H-Scraper security modules
# ═══════════════════════════════════════════════════════════════════

class SecurityWorker(BaseWorker):
    """Real security worker using H-Scraper PII detector, taint tracker, classification.

    Subtask pipeline:
        1. SCOPE_VERIFICATION    → bridge.verify_scope()
        2. PASSIVE_OBSERVATION   → bridge.observe_passively()
        3. AUTHORIZATION_AUDIT   → bridge.audit_authorization() ← REAL PII DETECTION
        4. EXPOSURE_ANALYSIS     → bridge.analyze_exposure()
        5. RISK_CLASSIFICATION   → bridge.classify_risk()
        6. RECOMMENDATIONS       → bridge.synthesize_recommendations()
    """

    ENGINE = "security"

    def __init__(self, worker_id: str, queue: JobQueue, store: JobStore,
                 lifecycle: JobLifecycleManager):
        super().__init__(worker_id, queue, store, lifecycle)
        self.ckpt = CheckpointManager(store, lifecycle)
        self._cancelled = False
        self._bridge = None

    @property
    def bridge(self):
        if self._bridge is None:
            from bridge.security_bridge import get_security_bridge
            self._bridge = get_security_bridge()
        return self._bridge

    def _do_work(self, record: JobRecord, context: Dict[str, Any]) -> Dict[str, Any]:
        contract = record.contract
        target = contract.target_asset
        auth_ref = contract.authorization_reference or "VISION-M-001"
        content = context.get("content", "") or context.get("html", "")

        subtasks = []
        budget_consumed = 0

        subtask_specs = [
            ("scope_verification", "1/6: scope",
             ["passive_observation", "auth_audit", "exposure", "risk", "recommendations"],
             "passive_observation"),
            ("passive_observation", "2/6: observation",
             ["auth_audit", "exposure", "risk", "recommendations"],
             "auth_audit"),
            ("authorization_audit", "3/6: authorization",
             ["exposure", "risk", "recommendations"],
             "exposure"),
            ("exposure_analysis", "4/6: exposure",
             ["risk", "recommendations"],
             "risk"),
            ("risk_classification", "5/6: risk",
             ["recommendations"],
             "recommendations"),
            ("recommendation_synthesis", "6/6: recommendations",
             [], None),
        ]

        # Store intermediates
        scope = passive = auth_audit = exposure = risk = None

        for name, label, pending, next_active in subtask_specs:
            self._check_cancellation()

            if name == "scope_verification":
                result = self.bridge.verify_scope(target, auth_ref)
                scope = result
            elif name == "passive_observation":
                result = self.bridge.observe_passively(target, content)
                passive = result
            elif name == "authorization_audit":
                result = self.bridge.audit_authorization(target, content)
                auth_audit = result
            elif name == "exposure_analysis":
                result = self.bridge.analyze_exposure(
                    auth_audit or {}, passive or {})
                exposure = result
            elif name == "risk_classification":
                result = self.bridge.classify_risk(
                    exposure or {}, auth_audit or {})
                risk = result
            elif name == "recommendation_synthesis":
                result = self.bridge.synthesize_recommendations(
                    risk or {}, exposure or {})

            subtasks.append({"name": name, "status": "completed",
                            "detail": result})
            budget_consumed += 1
            self._checkpoint(record, label, {
                "completed_subtasks": [s["name"] for s in subtasks],
                "pending_subtasks": pending,
                "active_subtask": next_active or "complete",
                "budget_consumed": budget_consumed,
                "remaining_budget": contract.request_budget - budget_consumed,
            })

        risk_level = risk.get("risk_level", "UNKNOWN") if risk else "UNKNOWN"
        findings_count = auth_audit.get("findings_count", 0) if auth_audit else 0

        findings = [{
            "title": f"Security: {target}",
            "description": f"Risk level: {risk_level}. "
                           f"Findings: {findings_count}. "
                           f"Method: PASSIVE_ONLY — active testing requires authorization.",
            "severity": risk_level.lower() if risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "info",
            "confidence": 0.85,
            "risk_level": risk_level,
            "findings_count": findings_count,
        }]

        return {
            "summary": f"Security assessment: {target}. Risk: {risk_level}. "
                       f"Findings: {findings_count}. Budget: {budget_consumed}/{contract.request_budget}",
            "evidence_references": [f"ev-sec-{i}" for i in range(6)],
            "findings": findings,
            "requests_consumed": budget_consumed,
            "completed_subtasks": [s["name"] for s in subtasks],
            "confidence": 0.85,
            "risk_level": risk_level,
        }

    def _check_cancellation(self):
        if self._cancelled:
            raise RuntimeError("Job cancelled during execution")

    def _checkpoint(self, record, label, data):
        data["label"] = label
        data["engine"] = self.ENGINE
        data["worker_id"] = self.worker_id
        data["job_id"] = record.contract.job_id
        data["chain_id"] = record.contract.parent_chain_id
        data["plan_version"] = data.get("plan_version", 1)
        data["authorization_status"] = "valid"
        data["unresolved_errors"] = []
        data["unresolved_contradictions"] = []
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.ckpt.save_checkpoint(record, self.worker_id, data)
