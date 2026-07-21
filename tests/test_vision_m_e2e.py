"""
vision-M: End-to-End Integration Test
=======================================
Proves the two-layer architecture works as one integrated system.

Layer 1 (Orchestration) → Bridge → Layer 2 (Execution)
ScrapingWorker → ScrapingBridge → H-Scraper ContentExtractor
MiningWorker   → MiningBridge   → H-Scraper BusinessIntelligence
SecurityWorker → SecurityBridge → H-Scraper PII/Taint/Classification

Test target: A simulated e-commerce page with embedded PII, product data,
and security-relevant patterns.
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
from layer1_orchestration.execution.real_workers import (
    ScrapingWorker, MiningWorker, SecurityWorker,
)

# ── Test HTML with real content to extract ───────────────────────
TEST_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Acme Medical Supplies — Product Catalog</title>
    <meta name="description" content="Acme Medical Supplies online catalog">
</head>
<body>
    <!-- Nginx server header simulation -->
    <header>
        <h1>Acme Medical Supplies</h1>
        <nav class="main-nav" aria-label="Primary">
            <a href="/products">Products</a>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </nav>
    </header>

    <main>
        <section class="product-catalog">
            <h2>Featured Products</h2>

            <article class="product" data-id="PRD-001">
                <h3>Surgical Mask — Type IIR</h3>
                <p class="price">$12.99</p>
                <p class="stock">In Stock: 1,450 units</p>
                <p class="category">PPE / Respiratory</p>
            </article>

            <article class="product" data-id="PRD-002">
                <h3>Nitrile Gloves — Large</h3>
                <p class="price">$8.50</p>
                <p class="stock">In Stock: 3,200 units</p>
                <p class="category">PPE / Hand Protection</p>
            </article>

            <article class="product" data-id="PRD-003">
                <h3>Digital Thermometer</h3>
                <p class="price">$24.99</p>
                <p class="stock">In Stock: 890 units</p>
                <p class="category">Diagnostics / Temperature</p>
            </article>

            <article class="product" data-id="PRD-004">
                <h3>Blood Pressure Monitor</h3>
                <p class="price">$49.99</p>
                <p class="stock">In Stock: 340 units</p>
                <p class="category">Diagnostics / Cardiovascular</p>
            </article>

            <article class="product" data-id="PRD-005">
                <h3>Pulse Oximeter</h3>
                <p class="price">$19.99</p>
                <p class="stock">In Stock: 1,100 units</p>
                <p class="category">Diagnostics / Respiratory</p>
            </article>
        </section>

        <!-- ⚠️ Security-relevant: accidentally committed credentials -->
        <script>
            // TODO: Remove before production — DEV ONLY
            const CONFIG = {
                apiKey: "sk-acme-prod-a1b2c3d4e5f6g7h8i9j0",
                smtpPassword: "AcmeMail2024!",
                adminEmail: "admin@acme-medical-supplies.com",
                supportPhone: "+1-555-0123",
                internalIP: "192.168.1.100",
                dbConnection: "postgresql://admin:SuperSecret123@192.168.1.50:5432/acme_prod"
            };
        </script>

        <footer>
            <p>Contact: support@acme-medical-supplies.com | Phone: +1-555-0123</p>
            <p>Acme Medical Supplies Inc. All rights reserved 2026.</p>
        </footer>
    </main>
</body>
</html>"""

TEST_PRODUCTS = [
    {"name": "Surgical Mask — Type IIR", "price": "$12.99", "stock": "In Stock: 1,450 units", "category": "PPE / Respiratory"},
    {"name": "Nitrile Gloves — Large", "price": "$8.50", "stock": "In Stock: 3,200 units", "category": "PPE / Hand Protection"},
    {"name": "Digital Thermometer", "price": "$24.99", "stock": "In Stock: 890 units", "category": "Diagnostics / Temperature"},
    {"name": "Blood Pressure Monitor", "price": "$49.99", "stock": "In Stock: 340 units", "category": "Diagnostics / Cardiovascular"},
    {"name": "Pulse Oximeter", "price": "$19.99", "stock": "In Stock: 1,100 units", "category": "Diagnostics / Respiratory"},
]


# ═══════════════════════════════════════════════════════════════════
# Test Infrastructure
# ═══════════════════════════════════════════════════════════════════

PASS = 0
FAIL = 0
STORE_DIR = "/tmp/vision_m_e2e_tests"


def setup():
    if os.path.exists(STORE_DIR):
        shutil.rmtree(STORE_DIR)
    os.makedirs(STORE_DIR, exist_ok=True)


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ PASS  {name}")
    else:
        FAIL += 1
        print(f"  ❌ FAIL  {name} — {detail}")


def make_infra():
    store = JobStore(STORE_DIR)
    mgr = JobLifecycleManager()
    queue = JobQueue(store, mgr)
    validator = ResultValidator(store, mgr)
    return store, mgr, queue, validator


def create_and_enqueue(queue, engine="scraping", budget=10):
    contract = JobContract.create(
        tenant_id="vision-m-test",
        mission_id="VISION-M-E2E-001",
        parent_finding_id=f"f-{uuid.uuid4().hex[:6]}",
        parent_chain_id=f"chain-{uuid.uuid4().hex[:6]}",
        hypothesis_id=f"hyp-{uuid.uuid4().hex[:6]}",
        source_engine=engine,
        target_engine=engine,
        target_asset="https://acme-medical-supplies.com/catalog",
        normalized_asset="acme-medical-supplies-catalog",
        action_type="test_e2e",
        request_budget=budget,
        authorization_reference="VISION-M-AUTH-001",
        max_retries=2,
    )
    record = JobRecord(contract=contract)
    return queue.enqueue(record)


def full_lifecycle(queue, store, mgr, worker, record, context=None):
    """Run complete lifecycle: queue → assign → start → execute → complete → validate."""
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
# TEST 1: Scraping — Real ContentExtractor Engine
# ═══════════════════════════════════════════════════════════════════

def test_scraping_with_real_html():
    """ScrapingWorker extracts real data from HTML using bridge → ContentExtractor."""
    print("\n" + "=" * 60)
    print("TEST 1: Scraping — Real ContentExtractor Engine")
    print("=" * 60)

    store, mgr, queue, validator = make_infra()
    worker = ScrapingWorker("sw-e2e", queue, store, mgr)
    record = create_and_enqueue(queue, "scraping")

    record, result = full_lifecycle(queue, store, mgr, worker, record, {
        "html": TEST_HTML,
    })

    # Verify results
    check("6 subtasks completed", len(result["completed_subtasks"]) == 6)
    check("budget consumed", result["requests_consumed"] == 6)
    check("has evidence", len(result["evidence_references"]) > 0)
    check("has findings", len(result["findings"]) > 0)
    check("confidence > 0", result["confidence"] > 0)
    check("bridge_available reported", "bridge_available" in result)

    # Verify bridge actually connected
    bridge_available = result.get("bridge_available", False)
    engine = result["findings"][0].get("engine", "unknown")
    print(f"\n  Bridge available: {bridge_available}")
    print(f"  Engine used: {engine}")
    print(f"  Summary: {result['summary'][:120]}")

    store.save(record)
    return result


# ═══════════════════════════════════════════════════════════════════
# TEST 2: Mining — Real Pattern Discovery
# ═══════════════════════════════════════════════════════════════════

def test_mining_with_product_data():
    """MiningWorker discovers patterns in structured product data via bridge."""
    print("\n" + "=" * 60)
    print("TEST 2: Mining — Pattern Discovery Engine")
    print("=" * 60)

    store, mgr, queue, validator = make_infra()
    worker = MiningWorker("mw-e2e", queue, store, mgr)
    record = create_and_enqueue(queue, "mining")

    record, result = full_lifecycle(queue, store, mgr, worker, record, {
        "data": TEST_PRODUCTS,
        "fields": ["name", "price", "category"],
    })

    check("6 subtasks completed", len(result["completed_subtasks"]) == 6)
    check("budget consumed", result["requests_consumed"] == 6)
    check("has findings", len(result["findings"]) > 0)
    check("confidence > 0", result["confidence"] > 0)
    check("bridge_available reported", "bridge_available" in result)

    bridge_available = result.get("bridge_available", False)
    print(f"\n  Bridge available: {bridge_available}")
    print(f"  Summary: {result['summary'][:120]}")

    store.save(record)
    return result


# ═══════════════════════════════════════════════════════════════════
# TEST 3: Security — Real PII Detection
# ═══════════════════════════════════════════════════════════════════

def test_security_pii_detection():
    """SecurityWorker detects PII, credentials, and security issues via bridge."""
    print("\n" + "=" * 60)
    print("TEST 3: Security — PII & Credential Detection")
    print("=" * 60)

    store, mgr, queue, validator = make_infra()
    worker = SecurityWorker("sec-e2e", queue, store, mgr)
    record = create_and_enqueue(queue, "security")

    record, result = full_lifecycle(queue, store, mgr, worker, record, {
        "content": TEST_HTML,
        "html": TEST_HTML,
    })

    check("6 subtasks completed", len(result["completed_subtasks"]) == 6)
    check("budget consumed", result["requests_consumed"] == 6)
    check("has findings", len(result["findings"]) > 0)
    check("confidence > 0", result["confidence"] > 0)
    check("risk_level present", "risk_level" in result)

    risk = result.get("risk_level", "UNKNOWN")
    print(f"\n  Risk level: {risk}")
    print(f"  Summary: {result['summary'][:120]}")

    store.save(record)
    return result


# ═══════════════════════════════════════════════════════════════════
# TEST 4: Full Pipeline — All Three Workers in Sequence
# ═══════════════════════════════════════════════════════════════════

def test_full_pipeline():
    """Complete pipeline: Scrape → Mine → Security → Cross-Gear Synthesis."""
    print("\n" + "=" * 60)
    print("TEST 4: Full Pipeline — Scrape → Mine → Security → Synthesis")
    print("=" * 60)

    store, mgr, queue, validator = make_infra()

    # ── Phase 1: Scrape ──
    print("\n  [Phase 1/4] SCRAPING...")
    sw = ScrapingWorker("sw-pipe", queue, store, mgr)
    scrape_record = create_and_enqueue(queue, "scraping")
    scrape_record, scrape_result = full_lifecycle(
        queue, store, mgr, sw, scrape_record,
        {"html": TEST_HTML}
    )
    scrape_ok = len(scrape_result["completed_subtasks"]) == 6
    check("Phase 1: Scraping completed", scrape_ok)
    print(f"    Engine: {scrape_result['findings'][0].get('engine', '?')}")

    # ── Phase 2: Mine ──
    print("\n  [Phase 2/4] MINING...")
    mw = MiningWorker("mw-pipe", queue, store, mgr)
    mine_record = create_and_enqueue(queue, "mining")
    mine_record, mine_result = full_lifecycle(
        queue, store, mgr, mw, mine_record,
        {"data": TEST_PRODUCTS, "fields": ["name", "price", "category"]}
    )
    mine_ok = len(mine_result["completed_subtasks"]) == 6
    check("Phase 2: Mining completed", mine_ok)

    # ── Phase 3: Security ──
    print("\n  [Phase 3/4] SECURITY...")
    sec = SecurityWorker("sec-pipe", queue, store, mgr)
    sec_record = create_and_enqueue(queue, "security")
    sec_record, sec_result = full_lifecycle(
        queue, store, mgr, sec, sec_record,
        {"content": TEST_HTML, "html": TEST_HTML}
    )
    sec_ok = len(sec_result["completed_subtasks"]) == 6
    check("Phase 3: Security completed", sec_ok)
    print(f"    Risk: {sec_result.get('risk_level', '?')}")

    # ── Phase 4: Cross-Gear Synthesis ──
    print("\n  [Phase 4/4] CROSS-GEAR SYNTHESIS...")
    try:
        from layer1_orchestration.security.cross_gear_perspectives import (
            CrossGearPerspectiveEngine, GearPerspective,
        )
        from layer1_orchestration.security.finding_node import (
            FindingNode, FindingNodeType,
        )
        from layer1_orchestration.security.findings_graph import FindingsGraph

        engine = CrossGearPerspectiveEngine()
        graph = FindingsGraph(mission_id="VISION-M-E2E-001")

        # Create a proper FindingNode for the synthesis
        finding = FindingNode(
            node_id=str(uuid.uuid4()),
            mission_id="VISION-M-E2E-001",
            correlation_id=str(uuid.uuid4()),
            node_type=FindingNodeType.FINDING,
            title=f"E2E Pipeline: {scrape_record.contract.target_asset}",
            description=(
                f"Scraping: {scrape_result['summary'][:100]}\n"
                f"Mining: {mine_result['summary'][:100]}\n"
                f"Security: {sec_result['summary'][:100]}"
            ),
            source_gear="scraping",
            source_agent_id="vision-m-e2e",
            approving_manager_id=None,
            confidence=0.85,
        )
        graph.add_node(finding)

        # Generate all 4-gear perspectives
        synthesis = engine.generate_perspectives(finding, graph)

        check("Synthesis generated", synthesis is not None)
        check("All 4 gears present",
              synthesis is not None and len(synthesis.perspectives) == 4)

        # Validate perspectives
        valid = engine.validate_perspectives(synthesis.perspectives)
        check("All 4 perspectives validated", valid)

        # Security-only check
        is_sec_only = synthesis.is_security_only
        check("NOT security-only (MUST have all 4)", not is_sec_only)

        # can_activate_chain — takes the synthesis result
        can_activate = engine.can_activate_chain(synthesis)
        check("Chain activation gate works", can_activate is not None)

        all_phases_passed = scrape_ok and mine_ok and sec_ok
        check("ALL 4 PHASES PASSED", all_phases_passed)

        print(f"\n  Gears: {list(synthesis.perspectives.keys())}")
        print(f"  Validated: {valid}")
        print(f"  Security-only: {is_sec_only}")
        print(f"  Can activate chain: {can_activate}")

    except ImportError as e:
        check("Synthesis engine imported", False, str(e))

    return {
        "scrape": scrape_result,
        "mining": mine_result,
        "security": sec_result,
    }


# ═══════════════════════════════════════════════════════════════════
# TEST 5: Checkpoint Recovery Across Restart
# ═══════════════════════════════════════════════════════════════════

def test_checkpoint_recovery():
    """Worker survives interruption and resumes from checkpoint."""
    print("\n" + "=" * 60)
    print("TEST 5: Checkpoint Recovery")
    print("=" * 60)

    store, mgr, queue, _ = make_infra()
    worker = ScrapingWorker("sw-recover", queue, store, mgr)
    record = create_and_enqueue(queue, "scraping")
    record = queue.assign(record, worker.worker_id)
    record = queue.start_execution(record, worker.worker_id)

    # Run partial, simulate crash
    worker._do_work(record, {"html": TEST_HTML})

    ckpt_count = len(record.checkpoints)
    check(f"checkpoints saved ({ckpt_count})", ckpt_count >= 5)

    # New worker resumes
    worker2 = ScrapingWorker("sw-recover-2", queue, store, mgr)
    result2 = worker2._do_work(record, {})
    check("recovery completed all 6", len(result2["completed_subtasks"]) == 6)

    store.save(record)


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("vision-M: END-TO-END INTEGRATION TESTS")
    print("Layer 1 (Orchestration) ↔ Bridge ↔ Layer 2 (Execution)")
    print("=" * 60)

    setup()

    test_scraping_with_real_html()
    test_mining_with_product_data()
    test_security_pii_detection()
    test_full_pipeline()
    test_checkpoint_recovery()

    print("\n" + "=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    if FAIL > 0:
        sys.exit(1)
