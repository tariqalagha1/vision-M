"""
vision-M: Quality Certification Suite
======================================
Comprehensive quality gate before repo push.

Tests:
  Gate 1: Project Structure Integrity
  Gate 2: Import Chain (no broken imports)
  Gate 3: Bridge Engine Integration (real H-Scraper connections)
  Gate 4: Worker Lifecycle (queue→assign→execute→complete→validate)
  Gate 5: Cross-Gear Synthesis (all 4 perspectives)
  Gate 6: Checkpoint & Recovery (fault tolerance)
  Gate 7: Budget Enforcement (resource limits)
  Gate 8: Error Resilience (graceful degradation)
  Gate 9: State Isolation (tenant/mission isolation)
  Gate 10: Full E2E Pipeline (scrape→mine→security→synthesis)
"""

from __future__ import annotations

import os
import sys
import uuid
import shutil
from datetime import datetime, timezone
from pathlib import Path

# ── Ensure vision-M is on path ───────────────────────────────────
_VISION_M = Path("/data/workspace/vision-M")
if str(_VISION_M) not in sys.path:
    sys.path.insert(0, str(_VISION_M))

from layer1_orchestration.execution.job_contract import (
    JobState, JobRecord, JobContract, ValidationDecision,
)
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_queue import JobQueue
from layer1_orchestration.execution.result_validator import ResultValidator
from bridge.scraping_bridge import ScrapingBridge, get_scraping_bridge
from bridge.mining_bridge import MiningBridge, get_mining_bridge
from bridge.security_bridge import SecurityBridge, get_security_bridge
from layer1_orchestration.execution.real_workers import (
    ScrapingWorker, MiningWorker, SecurityWorker,
)

# ── Test data ─────────────────────────────────────────────────────
TEST_HTML = """<!DOCTYPE html>
<html><head><title>ACME Corp — Enterprise Solutions</title>
<meta name="description" content="B2B enterprise software and cloud solutions">
</head><body>
<header><h1>ACME Corp</h1></header>
<main>
<table class="products">
<tr><th>Product</th><th>Price</th><th>Stock</th></tr>
<tr><td>CloudSync Pro</td><td>$299/mo</td><td>Unlimited</td></tr>
<tr><td>DataVault Enterprise</td><td>$599/mo</td><td>Unlimited</td></tr>
<tr><td>SecureFlow Gateway</td><td>$199/mo</td><td>Unlimited</td></tr>
<tr><td>Analytics Suite</td><td>$399/mo</td><td>Unlimited</td></tr>
</table>
<script>
// DEV CONFIG — REMOVE BEFORE PRODUCTION
const config = {
    apiKey: "sk-acme-prod-k8x9m2",
    dbPassword: "AcmeDB!2026!Prod",
    adminEmail: "ops@acme-corp.com",
    supportPhone: "+1-555-0199",
    internalService: "http://192.168.1.200:8080/admin",
};
</script>
<footer>© 2026 ACME Corp | ops@acme-corp.com | +1-555-0199</footer>
</body></html>"""

TEST_PRODUCTS = [
    {"name": "CloudSync Pro", "price": "$299/mo", "stock": "Unlimited"},
    {"name": "DataVault Enterprise", "price": "$599/mo", "stock": "Unlimited"},
    {"name": "SecureFlow Gateway", "price": "$199/mo", "stock": "Unlimited"},
    {"name": "Analytics Suite", "price": "$399/mo", "stock": "Unlimited"},
]

# ═══════════════════════════════════════════════════════════════════
# Test Harness
# ═══════════════════════════════════════════════════════════════════

class Gate:
    """Quality gate — counts passes, failures, and can halt on critical failure."""

    def __init__(self, name: str):
        self.name = name
        self.passed = 0
        self.failed = 0
        self.checks = []

    def check(self, name, condition, detail=""):
        if condition:
            self.passed += 1
            self.checks.append(f"  ✅ {name}")
        else:
            self.failed += 1
            self.checks.append(f"  ❌ {name} — {detail}" if detail else f"  ❌ {name}")

    def report(self) -> bool:
        print(f"\n{'='*60}")
        status = "✅ PASSED" if self.failed == 0 else "❌ FAILED"
        print(f"Gate {self.name}: {status}  ({self.passed}P / {self.failed}F / {self.passed + self.failed}T)")
        for c in self.checks:
            print(c)
        return self.failed == 0


STORE_DIR = "/tmp/vision_m_quality"


def setup():
    if os.path.exists(STORE_DIR):
        shutil.rmtree(STORE_DIR)
    os.makedirs(STORE_DIR, exist_ok=True)


def make_infra():
    store = JobStore(STORE_DIR)
    mgr = JobLifecycleManager()
    queue = JobQueue(store, mgr)
    validator = ResultValidator(store, mgr)
    return store, mgr, queue, validator


def enqueue(queue, engine, tenant="quality-test", budget=10):
    contract = JobContract.create(
        tenant_id=tenant,
        mission_id=f"QUALITY-{uuid.uuid4().hex[:6]}",
        parent_finding_id=f"f-{uuid.uuid4().hex[:6]}",
        parent_chain_id=f"chain-{uuid.uuid4().hex[:6]}",
        hypothesis_id=f"hyp-{uuid.uuid4().hex[:6]}",
        source_engine=engine,
        target_engine=engine,
        target_asset=f"https://{engine}-test.example.com",
        normalized_asset=f"{engine}-test",
        action_type="quality_test",
        request_budget=budget,
        authorization_reference="QUALITY-AUTH-001",
        max_retries=2,
    )
    return queue.enqueue(JobRecord(contract=contract))


def run_lifecycle(queue, store, mgr, worker, record, context=None):
    """Run full lifecycle: queue→assign→start→execute→complete."""
    record = queue.assign(record, worker.worker_id)
    record = queue.start_execution(record, worker.worker_id)
    result = worker._do_work(record, context or {})
    if record.current_state == "CHECKPOINTED":
        mgr.transition(record, JobState.RUNNING, actor=worker.worker_id)
    record.completion_result = result
    record.evidence_references = result.get("evidence_references", [])
    store.save(record)
    record = queue.complete_execution(record, worker.worker_id)
    return record, result


# ═══════════════════════════════════════════════════════════════════
# GATE 1: Project Structure Integrity
# ═══════════════════════════════════════════════════════════════════

def gate1_structure():
    g = Gate("G1 — Project Structure")

    required_dirs = [
        "layer1_orchestration/execution",
        "layer1_orchestration/discovery",
        "layer1_orchestration/security",
        "layer1_orchestration/orchestration",
        "layer2_execution/scraping",
        "layer2_execution/extraction",
        "layer2_execution/mining",
        "layer2_execution/security",
        "bridge",
        "tests",
    ]

    for d in required_dirs:
        path = _VISION_M / d
        g.check(f"dir exists: {d}", path.is_dir(),
                f"Missing at {path}")

    required_files = [
        "bridge/scraping_bridge.py",
        "bridge/mining_bridge.py",
        "bridge/security_bridge.py",
        "bridge/__init__.py",
        "layer1_orchestration/execution/real_workers.py",
        "layer1_orchestration/execution/job_contract.py",
        "layer1_orchestration/execution/job_queue.py",
        "layer1_orchestration/execution/job_store.py",
        "layer1_orchestration/execution/job_lifecycle.py",
        "layer1_orchestration/execution/worker_contract.py",
        "layer1_orchestration/security/cross_gear_perspectives.py",
        "layer1_orchestration/security/findings_graph.py",
        "layer1_orchestration/security/finding_node.py",
        "tests/test_vision_m_e2e.py",
        "pyproject.toml",
        "__init__.py",
    ]

    for f in required_files:
        path = _VISION_M / f
        g.check(f"file exists: {f}", path.is_file(),
                f"Missing at {path}")

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 2: Import Chain Integrity
# ═══════════════════════════════════════════════════════════════════

def gate2_imports():
    g = Gate("G2 — Import Chain")

    # Test each module imports cleanly
    modules = [
        ("bridge.scraping_bridge", "ScrapingBridge"),
        ("bridge.mining_bridge", "MiningBridge"),
        ("bridge.security_bridge", "SecurityBridge"),
        ("layer1_orchestration.execution.job_contract", "JobContract"),
        ("layer1_orchestration.execution.job_store", "JobStore"),
        ("layer1_orchestration.execution.job_queue", "JobQueue"),
        ("layer1_orchestration.execution.job_lifecycle", "JobLifecycleManager"),
        ("layer1_orchestration.execution.worker_contract", "BaseWorker"),
        ("layer1_orchestration.execution.real_workers", "ScrapingWorker"),
        ("layer1_orchestration.execution.real_workers", "MiningWorker"),
        ("layer1_orchestration.execution.real_workers", "SecurityWorker"),
        ("layer1_orchestration.security.cross_gear_perspectives",
         "CrossGearPerspectiveEngine"),
        ("layer1_orchestration.security.findings_graph", "FindingsGraph"),
        ("layer1_orchestration.security.finding_node", "FindingNode"),
        ("layer1_orchestration.security.dispatch_contract", "DispatchRequest"),
        ("layer1_orchestration.security.routing_matrix", "RoutingResolver"),
        ("layer1_orchestration.discovery.gear_engines", "ScrapingGearEngine"),
        ("layer1_orchestration.discovery.gear_engines", "MiningGearEngine"),
        ("layer1_orchestration.discovery.gear_engines", "SecurityGearEngine"),
        ("layer1_orchestration.discovery.discovery_types", "DiscoveryRecord"),
    ]

    for mod, cls in modules:
        try:
            m = __import__(mod, fromlist=[cls])
            obj = getattr(m, cls)
            g.check(f"import {mod}.{cls}", obj is not None)
        except Exception as e:
            g.check(f"import {mod}.{cls}", False, str(e)[:80])

    # Also verify singletons work
    try:
        sb = get_scraping_bridge()
        g.check("ScrapingBridge singleton", sb is not None)
        g.check("ScrapingBridge.available", isinstance(sb.available, bool),
                f"Got {sb.available}")
    except Exception as e:
        g.check("ScrapingBridge singleton", False, str(e)[:80])

    try:
        mb = get_mining_bridge()
        g.check("MiningBridge singleton", mb is not None)
        g.check("MiningBridge.available", isinstance(mb.available, bool),
                f"Got {mb.available}")
    except Exception as e:
        g.check("MiningBridge singleton", False, str(e)[:80])

    try:
        sb = get_security_bridge()
        g.check("SecurityBridge singleton", sb is not None)
    except Exception as e:
        g.check("SecurityBridge singleton", False, str(e)[:80])

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 3: Bridge Engine Integration
# ═══════════════════════════════════════════════════════════════════

def gate3_bridges():
    g = Gate("G3 — Bridge Integration")

    # ── Scraping Bridge ──
    print("\n  [Scraping Bridge]")
    sb = get_scraping_bridge()

    result = sb.validate_source("https://example.com/api/products")
    g.check("scrape: source validation", result["status"] == "valid")
    g.check("scrape: protocol detection", result["protocol"] in ("https", "api"))

    result = sb.validate_source("192.168.1.1")
    g.check("scrape: internal IP flagged",
            len(result.get("warnings", [])) > 0)

    result = sb.select_driver("https://api.example.com/v1/products")
    g.check("scrape: driver selection API", "API_DRIVER" in str(result))

    result = sb.select_driver("https://example.com", TEST_HTML)
    g.check("scrape: driver selection with HTML",
            len(result.get("available_drivers", [])) > 1)

    result = sb.acquire("https://acme-corp.com", TEST_HTML)
    g.check("scrape: acquisition returns result", "status" in result)
    g.check("scrape: acquisition has engine", "engine" in result)
    print(f"    Engine: {result.get('engine', '?')}")

    result = sb.collect_evidence("test", result)
    g.check("scrape: evidence collected", result["status"] == "collected")

    result = sb.verify([{"type": "test"}], {"bytes": 100, "engine": "test"})
    g.check("scrape: verification", result["status"] in ("verified", "partial"))

    # ── Mining Bridge ──
    print("\n  [Mining Bridge]")
    mb = get_mining_bridge()

    result = mb.assess_sufficiency(TEST_PRODUCTS, "test-source")
    g.check("mining: sufficiency assessment", "status" in result)
    g.check("mining: record count correct", result["record_count"] == 4)

    result = mb.establish_baseline(TEST_PRODUCTS)
    g.check("mining: baseline established", result["status"] == "established")
    g.check("mining: baseline has metrics", "metrics" in result)

    result = mb.discover_patterns(TEST_PRODUCTS, ["name", "price", "stock"])
    g.check("mining: patterns discovered", result["status"] == "completed")
    g.check("mining: patterns count >= 0", result["patterns_detected"] >= 0)

    result = mb.analyze_trends(TEST_PRODUCTS)
    g.check("mining: trends analyzed", result["status"] == "completed")

    result = mb.synthesize_insights(
        [{"pattern_type": "HIGH_CARDINALITY", "field": "name"}],
        {}, "test-source"
    )
    g.check("mining: insights synthesized", result["status"] == "synthesized")

    result = mb.validate_findings(
        [{"pattern_type": "BASIC_STATS"}],
        {"commercial_value": "MEDIUM"}
    )
    g.check("mining: findings validated", result["status"] == "validated")

    # ── Security Bridge ──
    print("\n  [Security Bridge]")
    sb_sec = get_security_bridge()

    result = sb_sec.verify_scope("https://example.com", "AUTH-001")
    g.check("sec: scope verification", result["status"] == "IN_SCOPE")

    result = sb_sec.verify_scope("https://example.gov", "AUTH-001")
    g.check("sec: gov domain blocked",
            result["status"] == "BLOCKED")

    result = sb_sec.observe_passively("https://acme-corp.com", TEST_HTML)
    g.check("sec: passive observation", result["status"] == "observed")
    g.check("sec: has observations", result["observation_count"] >= 0)

    result = sb_sec.audit_authorization("https://acme-corp.com", TEST_HTML)
    g.check("sec: auth audit", result["status"] == "audited")
    g.check("sec: findings detected", result["findings_count"] > 0,
            f"Expected >0 PII findings in test HTML, got {result['findings_count']}")
    print(f"    Security findings: {result['findings_count']}")

    result2 = sb_sec.analyze_exposure(result, {"security_observations": []})
    g.check("sec: exposure analysis", result2["status"] == "analyzed")
    g.check("sec: exposure level HIGH", result2["exposure_level"] == "HIGH",
            f"Got {result2['exposure_level']}")

    result3 = sb_sec.classify_risk(result2, result)
    g.check("sec: risk classification", result3["status"] == "classified")
    g.check("sec: risk CRITICAL or HIGH",
            result3["risk_level"] in ("CRITICAL", "HIGH"),
            f"Got {result3['risk_level']}")
    print(f"    Risk level: {result3['risk_level']}")

    result4 = sb_sec.synthesize_recommendations(result3, result2)
    g.check("sec: recommendations synthesized", result4["status"] == "synthesized")
    g.check("sec: has recommendations", result4["total_recommendations"] > 0)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 4: Worker Lifecycle
# ═══════════════════════════════════════════════════════════════════

def gate4_lifecycle():
    g = Gate("G4 — Worker Lifecycle")

    for engine in ["scraping", "mining", "security"]:
        print(f"\n  [{engine}]")
        store, mgr, queue, validator = make_infra()

        if engine == "scraping":
            worker = ScrapingWorker(f"w-{engine}", queue, store, mgr)
            ctx = {"html": TEST_HTML}
        elif engine == "mining":
            worker = MiningWorker(f"w-{engine}", queue, store, mgr)
            ctx = {"data": TEST_PRODUCTS}
        else:
            worker = SecurityWorker(f"w-{engine}", queue, store, mgr)
            ctx = {"content": TEST_HTML, "html": TEST_HTML}

        record = enqueue(queue, engine)
        g.check(f"{engine}: queued", record.current_state == "QUEUED")

        record = queue.assign(record, worker.worker_id)
        g.check(f"{engine}: assigned", record.current_state == "ASSIGNED")

        record = queue.start_execution(record, worker.worker_id)
        g.check(f"{engine}: running", record.current_state == "RUNNING")

        result = worker._do_work(record, ctx)
        g.check(f"{engine}: 6 subtasks",
                len(result["completed_subtasks"]) == 6)
        g.check(f"{engine}: budget consumed",
                result["requests_consumed"] == 6)
        g.check(f"{engine}: has findings",
                len(result["findings"]) > 0)

        if record.current_state == "CHECKPOINTED":
            mgr.transition(record, JobState.RUNNING, actor=worker.worker_id)

        record.completion_result = result
        record.evidence_references = result.get("evidence_references", [])
        store.save(record)
        record = queue.complete_execution(record, worker.worker_id)
        g.check(f"{engine}: completed", record.current_state == "COMPLETED")

        # Validate
        result = validator.validate(record, f"validator-{engine}")
        g.check(f"{engine}: validated",
                result is not None and isinstance(result, dict))

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 5: Cross-Gear Synthesis
# ═══════════════════════════════════════════════════════════════════

def gate5_synthesis():
    g = Gate("G5 — Cross-Gear Synthesis")

    from layer1_orchestration.security.cross_gear_perspectives import (
        CrossGearPerspectiveEngine, GearPerspective,
    )
    from layer1_orchestration.security.finding_node import (
        FindingNode, FindingNodeType,
    )
    from layer1_orchestration.security.findings_graph import FindingsGraph

    # Test 1: Generate all 4 perspectives
    engine = CrossGearPerspectiveEngine()
    graph = FindingsGraph(mission_id="QUALITY-SYNTH-001")

    finding = FindingNode(
        node_id=str(uuid.uuid4()),
        mission_id="QUALITY-SYNTH-001",
        correlation_id=str(uuid.uuid4()),
        node_type=FindingNodeType.FINDING,
        title="Test Finding: API Exposure",
        description="An API endpoint was discovered serving structured data without authentication.",
        source_gear="scraping",
        source_agent_id="quality-agent",
        approving_manager_id=None,
        confidence=0.75,
        observed_fact="GET /api/products returns 200 without auth header",
        inferred_meaning="The endpoint may expose data without access control",
    )
    graph.add_node(finding)

    result = engine.generate_perspectives(finding, graph)
    g.check("generated", result is not None)
    g.check("4 gears", len(result.perspectives) == 4)
    g.check("gears: scraping", "scraping" in result.perspectives)
    g.check("gears: mining", "mining" in result.perspectives)
    g.check("gears: security", "security" in result.perspectives)
    g.check("gears: evidence", "evidence" in result.perspectives)

    # Test 2: Validate perspectives
    valid = engine.validate_perspectives(result.perspectives)
    g.check("all 4 validated", valid)

    # Test 3: Security-only detection (ensuring NOT security-only)
    is_sec_only = result.is_security_only
    g.check("NOT security-only", not is_sec_only,
            "Cross-gear violated: security-only interpretation")

    # Test 4: Chain activation
    can_activate = engine.can_activate_chain(result)
    g.check("chain can activate", can_activate)

    # Test 5: Security-only blocking
    sec_only_result = engine._results.get(finding.node_id)
    if sec_only_result:
        g.check("security-only count 0",
                engine._security_only_blocked == 0)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 6: Checkpoint & Recovery
# ═══════════════════════════════════════════════════════════════════

def gate6_recovery():
    g = Gate("G6 — Checkpoint & Recovery")

    store, mgr, queue, _ = make_infra()

    worker = ScrapingWorker("w-recover", queue, store, mgr)
    record = enqueue(queue, "scraping")
    record = queue.assign(record, worker.worker_id)
    record = queue.start_execution(record, worker.worker_id)

    # Execute (should create 5 checkpoints)
    worker._do_work(record, {"html": TEST_HTML})

    g.check("checkpoints saved", len(record.checkpoints) >= 5,
            f"Got {len(record.checkpoints)}")
    g.check("checkpoints have labels",
            all("label" in ckpt.get("data", ckpt) for ckpt in record.checkpoints))
    g.check("checkpoints have budget",
            all("budget_consumed" in ckpt.get("data", ckpt)
                for ckpt in record.checkpoints))

    # Simulate crash — new worker resumes
    worker2 = ScrapingWorker("w-recover-2", queue, store, mgr)
    result = worker2._do_work(record, {"html": TEST_HTML})
    g.check("recovery: all 6 subtasks",
            len(result["completed_subtasks"]) == 6)

    store.save(record)

    # Test: recovery for mining worker
    mworker = MiningWorker("mw-recover", queue, store, mgr)
    mrecord = enqueue(queue, "mining")
    mrecord = queue.assign(mrecord, mworker.worker_id)
    mrecord = queue.start_execution(mrecord, mworker.worker_id)
    mworker._do_work(mrecord, {"data": TEST_PRODUCTS})
    g.check("mining: checkpoints", len(mrecord.checkpoints) >= 5,
            f"Got {len(mrecord.checkpoints)}")

    # Test: recovery for security worker
    sw = SecurityWorker("sw-recover", queue, store, mgr)
    srecord = enqueue(queue, "security")
    srecord = queue.assign(srecord, sw.worker_id)
    srecord = queue.start_execution(srecord, sw.worker_id)
    sw._do_work(srecord, {"content": TEST_HTML, "html": TEST_HTML})
    g.check("security: checkpoints", len(srecord.checkpoints) >= 5,
            f"Got {len(srecord.checkpoints)}")

    store.save(mrecord)
    store.save(srecord)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 7: Budget Enforcement
# ═══════════════════════════════════════════════════════════════════

def gate7_budget():
    g = Gate("G7 — Budget Enforcement")

    store, mgr, queue, _ = make_infra()

    # Each worker should consume exactly 6 units (one per subtask)
    worker = ScrapingWorker("w-budget", queue, store, mgr)
    record = enqueue(queue, "scraping", budget=10)
    _, result = run_lifecycle(queue, store, mgr, worker, record,
                               {"html": TEST_HTML})

    consumed = result["requests_consumed"]
    budget = record.contract.request_budget
    g.check("scraping: consumed <= budget", consumed <= budget)
    g.check("scraping: consumed exactly 6", consumed == 6,
            f"Expected 6, got {consumed}")

    # Mining
    mw = MiningWorker("mw-budget", queue, store, mgr)
    mrec = enqueue(queue, "mining", budget=10)
    _, mres = run_lifecycle(queue, store, mgr, mw, mrec,
                             {"data": TEST_PRODUCTS})
    g.check("mining: consumed exactly 6", mres["requests_consumed"] == 6)

    # Security
    sw = SecurityWorker("sw-budget", queue, store, mgr)
    srec = enqueue(queue, "security", budget=10)
    _, sres = run_lifecycle(queue, store, mgr, sw, srec,
                            {"content": TEST_HTML, "html": TEST_HTML})
    g.check("security: consumed exactly 6", sres["requests_consumed"] == 6)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 8: Error Resilience
# ═══════════════════════════════════════════════════════════════════

def gate8_resilience():
    g = Gate("G8 — Error Resilience")

    # Test: bridge graceful degradation when engines unavailable
    sb = get_scraping_bridge()

    # Empty content should not crash
    try:
        result = sb.acquire("test", "")
        g.check("scrape: empty HTML handled", "status" in result)
    except Exception as e:
        g.check("scrape: empty HTML handled", False, str(e)[:80])

    # Invalid target should not crash
    try:
        result = sb.validate_source("")
        g.check("scrape: empty target handled", result["status"] == "invalid")
    except Exception as e:
        g.check("scrape: empty target handled", False, str(e)[:80])

    # MB: empty data
    mb = get_mining_bridge()
    try:
        result = mb.assess_sufficiency([], "empty")
        g.check("mining: empty data handled", result["status"] == "INSUFFICIENT")
    except Exception as e:
        g.check("mining: empty data handled", False, str(e)[:80])

    # MB: empty data baseline
    try:
        result = mb.establish_baseline([])
        g.check("mining: empty baseline", result["status"] == "established")
    except Exception as e:
        g.check("mining: empty baseline", False, str(e)[:80])

    # SB_sec: empty content
    sb_sec = get_security_bridge()
    try:
        result = sb_sec.audit_authorization("test", "")
        g.check("sec: empty content audit", result["status"] == "audited")
        g.check("sec: empty content = 0 findings",
                result["findings_count"] == 0)
    except Exception as e:
        g.check("sec: empty content audit", False, str(e)[:80])

    # Worker resilience: missing context
    store, mgr, queue, _ = make_infra()
    worker = ScrapingWorker("w-resilient", queue, store, mgr)
    record = enqueue(queue, "scraping")
    try:
        _, result = run_lifecycle(queue, store, mgr, worker, record, {})
        g.check("worker: empty context handled",
                len(result["completed_subtasks"]) == 6)
    except Exception as e:
        g.check("worker: empty context handled", False, str(e)[:80])

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 9: State Isolation
# ═══════════════════════════════════════════════════════════════════

def gate9_isolation():
    g = Gate("G9 — State Isolation")

    store, mgr, queue, _ = make_infra()

    # Create two tenants with separate jobs
    worker = ScrapingWorker("w-iso", queue, store, mgr)

    reco1 = enqueue(queue, "scraping", tenant="tenant-alpha")
    reco2 = enqueue(queue, "scraping", tenant="tenant-beta")

    g.check("tenant-alpha queued", reco1.current_state == "QUEUED")
    g.check("tenant-beta queued", reco2.current_state == "QUEUED")
    g.check("different tenants",
            reco1.contract.tenant_id != reco2.contract.tenant_id)

    # Run both through lifecycle
    reco1, _ = run_lifecycle(queue, store, mgr, worker, reco1,
                              {"html": TEST_HTML})
    reco2, _ = run_lifecycle(queue, store, mgr, worker, reco2,
                              {"html": TEST_HTML})

    g.check("tenant-alpha completed", reco1.current_state == "COMPLETED")
    g.check("tenant-beta completed", reco2.current_state == "COMPLETED")

    # Verify different job IDs (true isolation)
    g.check("different job IDs",
            reco1.contract.job_id != reco2.contract.job_id)

    # Both should be in store
    j1 = store.load(reco1.contract.job_id)
    j2 = store.load(reco2.contract.job_id)
    g.check("both persisted", j1 is not None and j2 is not None)
    g.check("persisted tenants distinct",
            j1.contract.tenant_id != j2.contract.tenant_id)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# GATE 10: Full E2E Pipeline
# ═══════════════════════════════════════════════════════════════════

def gate10_e2e():
    g = Gate("G10 — Full E2E Pipeline")

    store, mgr, queue, validator = make_infra()

    # Phase 1: Scrape
    sw = ScrapingWorker("sw-e2e", queue, store, mgr)
    srec = enqueue(queue, "scraping", tenant="e2e-tenant")
    srec, sres = run_lifecycle(queue, store, mgr, sw, srec,
                                {"html": TEST_HTML})
    g.check("P1: scrape completed", len(sres["completed_subtasks"]) == 6)

    # Phase 2: Mine
    mw = MiningWorker("mw-e2e", queue, store, mgr)
    mrec = enqueue(queue, "mining", tenant="e2e-tenant")
    mrec, mres = run_lifecycle(queue, store, mgr, mw, mrec,
                                {"data": TEST_PRODUCTS})
    g.check("P2: mining completed", len(mres["completed_subtasks"]) == 6)

    # Phase 3: Security
    sec = SecurityWorker("sec-e2e", queue, store, mgr)
    secrec = enqueue(queue, "security", tenant="e2e-tenant")
    secrec, secres = run_lifecycle(queue, store, mgr, sec, secrec,
                                    {"content": TEST_HTML, "html": TEST_HTML})
    g.check("P3: security completed", len(secres["completed_subtasks"]) == 6)

    # Phase 4: Cross-Gear Synthesis
    from layer1_orchestration.security.cross_gear_perspectives import (
        CrossGearPerspectiveEngine,
    )
    from layer1_orchestration.security.finding_node import (
        FindingNode, FindingNodeType,
    )
    from layer1_orchestration.security.findings_graph import FindingsGraph

    engine = CrossGearPerspectiveEngine()
    graph = FindingsGraph(mission_id="E2E-FINAL")

    finding = FindingNode(
        node_id=str(uuid.uuid4()),
        mission_id="E2E-FINAL",
        correlation_id=str(uuid.uuid4()),
        node_type=FindingNodeType.FINDING,
        title=f"E2E Pipeline: {srec.contract.target_asset}",
        description=(
            f"Scraping: {sres['summary'][:80]}\n"
            f"Mining: {mres['summary'][:80]}\n"
            f"Security: {secres['summary'][:80]}"
        ),
        source_gear="scraping",
        source_agent_id="e2e-agent",
        approving_manager_id=None,
        confidence=0.85,
    )
    graph.add_node(finding)

    synthesis = engine.generate_perspectives(finding, graph)
    g.check("P4: synthesis generated", synthesis is not None)
    g.check("P4: all 4 gears", len(synthesis.perspectives) == 4)
    g.check("P4: validated", engine.validate_perspectives(synthesis.perspectives))
    g.check("P4: NOT security-only", not synthesis.is_security_only)
    g.check("P4: chain activatable", engine.can_activate_chain(synthesis))

    # Final validation: all jobs survived store
    for rec in [srec, mrec, secrec]:
        loaded = store.load(rec.contract.job_id)
        g.check(f"persisted: {rec.contract.job_id[:8]}", loaded is not None)

    # All 3 phases must pass
    all_ok = (len(sres["completed_subtasks"]) == 6 and
              len(mres["completed_subtasks"]) == 6 and
              len(secres["completed_subtasks"]) == 6)
    g.check("P1+P2+P3+P4 ALL PASSED", all_ok)

    return g.report()


# ═══════════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("vision-M: QUALITY CERTIFICATION SUITE")
    print("=" * 60)
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    setup()

    gates = [
        gate1_structure,
        gate2_imports,
        gate3_bridges,
        gate4_lifecycle,
        gate5_synthesis,
        gate6_recovery,
        gate7_budget,
        gate8_resilience,
        gate9_isolation,
        gate10_e2e,
    ]

    results = []
    for gate_fn in gates:
        passed = gate_fn()
        results.append(passed)

    # ── Summary ──
    total = len(results)
    passed = sum(results)
    failed = total - passed

    print("\n" + "=" * 60)
    print(f"FINAL VERDICT: {passed}/{total} gates passed")

    if failed == 0:
        print("CERTIFICATION: ✅ QUALIFIED FOR REPO PUSH")
    else:
        print(f"CERTIFICATION: ❌ BLOCKED — {failed} gate(s) failed")

    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
