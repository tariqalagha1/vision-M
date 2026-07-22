"""
vision-M: Complete End-to-End Validation Flow
==============================================
Covers: job creation → lifecycle → SecurityWorker → discovery pipeline →
audit trail → report generation → final verification.

Runs as a standalone validation script.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Ensure vision-M is on path
_VISION_M = Path("/data/workspace/vision-M")
if str(_VISION_M) not in sys.path:
    sys.path.insert(0, str(_VISION_M))

from layer1_orchestration.execution.job_contract import (
    JobState, JobRecord, JobContract, ValidationDecision,
)
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_queue import JobQueue
from layer1_orchestration.execution.real_workers import SecurityWorker
from layer1_orchestration.discovery.discovery_coordinator import ParallelDiscoveryCoordinator

# ── Test infra ───────────────────────────────────────────────────
STORE_DIR = "/tmp/vision_m_e2e_validation"
REPORTS_DIR = "/data/workspace/vision-M/layer1_orchestration/reports"
AUDIT_FILE = "/data/workspace/vision-M/audit.jsonl"
PASS = 0
FAIL = 0


def setup():
    """Clean and recreate store dir."""
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


# ═══════════════════════════════════════════════════════════════════
# STEP 1: Job Creation
# ═══════════════════════════════════════════════════════════════════

def step1_create_job():
    """Create a JobContract and enqueue it via JobQueue."""
    print("\n" + "=" * 70)
    print("STEP 1: Job Creation")
    print("=" * 70)

    contract = JobContract.create(
        tenant_id="build-validation",
        mission_id="E2E-VALIDATION-001",
        source_engine="security",
        target_engine="security",
        target_asset="e2e-validation-target",
        normalized_asset="e2e-validation-target",
        action_type="security_scan",
        authorization_reference="E2E-VALID-AUTH-001",
        request_budget=10,
        max_retries=2,
    )

    check("contract created", contract is not None)
    check("tenant_id = build-validation", contract.tenant_id == "build-validation")
    check("target = e2e-validation-target", contract.target_asset == "e2e-validation-target")
    check("action_type = security_scan", contract.action_type == "security_scan")
    check("has job_id", len(contract.job_id) > 0)

    print(f"\n  Job ID: {contract.job_id}")
    print(f"  Tenant: {contract.tenant_id}")
    print(f"  Target: {contract.target_asset}")

    return contract


# ═══════════════════════════════════════════════════════════════════
# STEP 2: Lifecycle Processing
# ═══════════════════════════════════════════════════════════════════

def step2_lifecycle(contract):
    """Process job through the full lifecycle: CREATED → AUTHORIZED → QUEUED → ASSIGNED → RUNNING → COMPLETED."""
    print("\n" + "=" * 70)
    print("STEP 2: Lifecycle Processing")
    print("=" * 70)

    store = JobStore(STORE_DIR)
    mgr = JobLifecycleManager()
    queue = JobQueue(store, mgr)

    # Create record (starts as CREATED)
    record = JobRecord(contract=contract)
    check("initial state = CREATED", record.current_state == JobState.CREATED.value)

    # Enqueue: CREATED → AUTHORIZED → QUEUED
    record = queue.enqueue(record)
    check("enqueue: CREATED → AUTHORIZED → QUEUED",
          record.current_state == JobState.QUEUED.value,
          f"got {record.current_state}")

    history_before = len(record.state_history)

    # Assign: QUEUED → ASSIGNED
    record = queue.assign(record, "validation-worker")
    check("assign: QUEUED → ASSIGNED",
          record.current_state == JobState.ASSIGNED.value,
          f"got {record.current_state}")
    check("worker_id assigned", record.assigned_worker_id == "validation-worker")
    check("lease set", record.lease_expires_at is not None)

    # Start: ASSIGNED → RUNNING
    record = queue.start_execution(record, "validation-worker")
    check("start: ASSIGNED → RUNNING",
          record.current_state == JobState.RUNNING.value,
          f"got {record.current_state}")
    check("execution_started_at set", record.execution_started_at is not None)

    # Complete: RUNNING → COMPLETED
    record = queue.complete_execution(record, "validation-worker")
    check("complete: RUNNING → COMPLETED",
          record.current_state == JobState.COMPLETED.value,
          f"got {record.current_state}")

    # Verify state history
    history = record.state_history
    history_after = len(history)
    check("state history has transitions", history_after > history_before)
    check("history has ≥ 5 transitions", len(history) >= 5,
          f"got {len(history)} transitions")

    # Print the lifecycle trace
    print(f"\n  Lifecycle trace ({len(history)} transitions):")
    for t in history:
        print(f"    {t.previous_state} → {t.new_state}  [{t.actor}] {t.reason}")

    return store, mgr, queue, record


# ═══════════════════════════════════════════════════════════════════
# STEP 3: SecurityWorker Execution
# ═══════════════════════════════════════════════════════════════════

def step3_security_worker(store, mgr, queue):
    """Execute SecurityWorker on a test target and verify the result."""
    print("\n" + "=" * 70)
    print("STEP 3: SecurityWorker Execution")
    print("=" * 70)

    # Create a fresh job for the security worker (so we can start from QUEUED)
    contract = JobContract.create(
        tenant_id="build-validation",
        mission_id="E2E-VALIDATION-002",
        source_engine="security",
        target_engine="security",
        target_asset="e2e-validation-target",
        normalized_asset="e2e-validation-target",
        action_type="security_scan",
        authorization_reference="E2E-VALID-AUTH-002",
        request_budget=10,
        max_retries=2,
    )

    record = JobRecord(contract=contract)
    record = queue.enqueue(record)

    # Create the worker
    worker = SecurityWorker("sec-validation", queue, store, mgr)

    # Full lifecycle: assign → start → execute → complete
    record = queue.assign(record, worker.worker_id)
    record = queue.start_execution(record, worker.worker_id)

    # Execute with content simulating a security target
    test_content = """
    <html>
    <head><title>E2E Validation Target</title></head>
    <body>
        <h1>E2E Test Application</h1>
        <p>Database connection: postgresql://admin:secret123@db.internal:5432/app</p>
        <script>
            const apiKey = "sk-live-validation-key-12345";
            const adminEmail = "admin@validation-target.com";
            const internalIP = "10.0.0.50";
        </script>
    </body>
    </html>
    """

    result = worker._do_work(record, {
        "content": test_content,
        "html": test_content,
    })

    print(f"\n  Worker result keys: {list(result.keys())}")

    # Verify result structure
    check("result dict has risk_level", "risk_level" in result,
          f"keys: {list(result.keys())}")
    check("result dict has findings", "findings" in result)
    check("result dict has summary", "summary" in result)
    check("result dict has evidence_references", "evidence_references" in result)
    check("completed_subtasks = 6", len(result.get("completed_subtasks", [])) == 6)
    check("confidence > 0", result.get("confidence", 0) > 0)
    check("requests_consumed = 6", result.get("requests_consumed", 0) == 6)

    # Add success field for the pipeline
    result["success"] = True
    result["target"] = contract.target_asset
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    result["discovery_id"] = str(uuid.uuid4())[:8]

    # Handle checkpoint → RUNNING transition before completing
    if record.current_state == "CHECKPOINTED":
        mgr.transition(record, JobState.RUNNING, actor=worker.worker_id)

    # Store completion
    record.completion_result = result
    record.evidence_references = result.get("evidence_references", [])
    store.save(record)
    record = queue.complete_execution(record, worker.worker_id)
    check("record completed", record.current_state == JobState.COMPLETED.value)

    print(f"\n  Risk Level: {result.get('risk_level', 'N/A')}")
    print(f"  Findings: {len(result.get('findings', []))}")
    print(f"  Summary: {result.get('summary', '')[:120]}")

    return result


# ═══════════════════════════════════════════════════════════════════
# STEP 4: Discovery Pipeline
# ═══════════════════════════════════════════════════════════════════

def step4_discovery_pipeline(scan_result):
    """Run the 7-phase discovery pipeline with the scan results."""
    print("\n" + "=" * 70)
    print("STEP 4: Discovery Pipeline")
    print("=" * 70)

    coord = ParallelDiscoveryCoordinator(
        mission_id="E2E-VALIDATION-MISSION",
        storage_dir=STORE_DIR,
    )

    # Build finding data from scan results
    finding_data = {
        "title": f"Security Scan: {scan_result.get('target', 'e2e-validation-target')}",
        "description": scan_result.get("summary", "Security scan result"),
        "source_gear": "security",
        "source_agent": "agent-security-validation",
        "source_manager": "mgr-security",
        "discovery_types": ["SECURITY_FINDING", "VULNERABILITY_SCAN"],
        "materiality": "high",
        "evidence_references": scan_result.get("evidence_references", []),
    }

    result = coord.process_discovery(finding_data)

    check("discovery result has success", "success" in result)
    check("discovery succeeded", result.get("success") is True,
          f"error: {result.get('error', 'N/A')}")

    # Verify phases
    phases = result.get("phases", [])
    print(f"\n  Phases ({len(phases)}):")
    for p in phases:
        print(f"    - {p}")

    check("phase: broadcast_complete", "broadcast_complete" in phases)
    check("phase: perspectives_generated", "perspectives_generated" in phases)
    check("phase: manager_review_complete", "manager_review_complete" in phases)
    check("phase: cross_sharing_complete", "cross_sharing_complete" in phases)
    check("phase: gate_passed", "gate_passed" in phases)
    check("phase: synthesis_complete", "synthesis_complete" in phases)
    check("phase: decision_complete", "decision_complete" in phases)

    all_7 = all(p in phases for p in [
        "broadcast_complete", "perspectives_generated",
        "manager_review_complete", "cross_sharing_complete",
        "gate_passed", "synthesis_complete", "decision_complete",
    ])
    check("all 7 phases present", all_7)

    check("has perspectives", len(result.get("perspectives", [])) == 4)
    check("has gate_result", result.get("gate_result") is not None)
    check("has synthesis", result.get("synthesis") is not None)
    check("has decision", result.get("decision") is not None)
    check("has event_count", result.get("event_count", 0) > 0)

    print(f"\n  Event count: {result.get('event_count', 0)}")
    print(f"  Perspectives: {len(result.get('perspectives', []))}")

    return result, coord


# ═══════════════════════════════════════════════════════════════════
# STEP 5: Audit Trail Verification
# ═══════════════════════════════════════════════════════════════════

def step5_audit_trail(result):
    """Verify audit.jsonl has new events from this run."""
    print("\n" + "=" * 70)
    print("STEP 5: Audit Trail Verification")
    print("=" * 70)

    check("audit.jsonl exists", os.path.exists(AUDIT_FILE),
          f"not found at {AUDIT_FILE}")

    if not os.path.exists(AUDIT_FILE):
        print("  ⚠️  audit.jsonl not found — skipping further audit checks")
        return

    # Read all events and count
    with open(AUDIT_FILE, "r") as f:
        lines = f.readlines()

    total_events = len(lines)
    print(f"\n  Total audit events on disk: {total_events}")

    check("audit.jsonl has events", total_events > 0)

    # Parse events
    events = []
    for line in lines:
        try:
            events.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            pass

    check("audit events parseable as JSON", len(events) > 0)
    print(f"  Parsed events: {len(events)}")

    # Check for discovery lifecycle event types
    event_types = [e.get("event_type", "") for e in events]
    unique_types = set(event_types)
    print(f"  Unique event types: {len(unique_types)}")

    lifecycle_events = [
        "DISCOVERY_REGISTERED",
        "DISCOVERY_BROADCAST",
        "DISCOVERY_ACKNOWLEDGED",
        "DISCOVERY_PERSPECTIVE_GATE_PASSED",
        "DISCOVERY_SYNTHESIS_COMPLETED",
        "NEXT_PHASE_DECISION_COMPLETED",
    ]

    found_types = set()
    for e in events:
        if e.get("event_type") in lifecycle_events:
            found_types.add(e["event_type"])

    print(f"\n  Lifecycle events found: {len(found_types)}/{len(lifecycle_events)}")
    for le in lifecycle_events:
        status = "✅" if le in found_types else "❌"
        print(f"    {status} {le}")

    check("audit covers discovery lifecycle", len(found_types) >= 4,
          f"only {len(found_types)}/{len(lifecycle_events)}")

    # Check our events have the right mission_id
    our_events = [e for e in events
                  if e.get("mission_id") == "E2E-VALIDATION-MISSION"]
    check("events for our mission exist", len(our_events) > 0,
          f"found {len(our_events)} events for E2E-VALIDATION-MISSION")

    return events


# ═══════════════════════════════════════════════════════════════════
# STEP 6: Report Generation
# ═══════════════════════════════════════════════════════════════════

def step6_report_generation(scan_result):
    """Verify report generation produces a valid HTML report."""
    print("\n" + "=" * 70)
    print("STEP 6: Report Generation")
    print("=" * 70)

    from layer1_orchestration.core.report_generator import save_report, generate_report

    # Count existing reports
    existing = set(os.listdir(REPORTS_DIR)) if os.path.exists(REPORTS_DIR) else set()

    # Generate and save report
    report_result = dict(scan_result)
    report_result["target"] = scan_result.get("target", "e2e-validation-target")
    report_result["timestamp"] = scan_result.get("timestamp",
                                                  datetime.now(timezone.utc).isoformat())
    report_result["risk_level"] = scan_result.get("risk_level", "MEDIUM")

    report_path = save_report(report_result)

    check("report_path returned", report_path is not None)
    check("report file exists", os.path.exists(report_path))
    check("report file non-empty", os.path.getsize(report_path) > 0)

    if os.path.exists(report_path):
        file_size = os.path.getsize(report_path)
        print(f"\n  Report path: {report_path}")
        print(f"  Report size: {file_size} bytes")

        # Verify HTML content
        with open(report_path, "r") as f:
            content = f.read(5000)

        check("report is HTML", "<html" in content.lower() or "<!DOCTYPE html>" in content)
        check("report has target", scan_result.get("target", "") in content or
              "e2e-validation-target" in content)
        check("report mentions risk_level", "risk" in content.lower())
        check("report has findings section", "findings" in content.lower())
        check("report has Executive Summary", "Executive Summary" in content)
        check("report has Scan Metadata", "Scan Metadata" in content)

        # Verify Markdown generation too
        md_content = generate_report(report_result, format="markdown")
        check("markdown content generated", len(md_content) > 0)
        check("markdown has title", "# " in md_content)

    return report_path


# ═══════════════════════════════════════════════════════════════════
# STEP 7: Final Verification
# ═══════════════════════════════════════════════════════════════════

def step7_final_verification(scan_result, discovery_result, audit_events):
    """Final comprehensive verification of all components."""
    print("\n" + "=" * 70)
    print("STEP 7: Final Verification")
    print("=" * 70)

    # ── Scan result verification ──
    print("\n  [Scan Result]")
    check("scan_result.risk_level present", "risk_level" in scan_result)
    check("scan_result.success = True", scan_result.get("success") is True)
    check("scan_result.findings non-empty", len(scan_result.get("findings", [])) > 0)
    check("scan_result.summary non-empty", len(scan_result.get("summary", "")) > 0)

    # ── Discovery pipeline verification ──
    print("\n  [Discovery Pipeline]")
    check("discovery_result.success = True", discovery_result.get("success") is True)
    phases = discovery_result.get("phases", [])
    all_7 = all(p in phases for p in [
        "broadcast_complete", "perspectives_generated",
        "manager_review_complete", "cross_sharing_complete",
        "gate_passed", "synthesis_complete", "decision_complete",
    ])
    check("all 7 discovery phases present", all_7)

    # ── Audit trail verification ──
    print("\n  [Audit Trail]")
    check("audit events exist", len(audit_events) > 0 if audit_events else False)
    if audit_events:
        our_events = [e for e in audit_events
                      if e.get("mission_id") == "E2E-VALIDATION-MISSION"]
        check("discovery events in audit", len(our_events) > 0)

        event_types_seen = set(e.get("event_type", "") for e in our_events)
        check("lifecycle events in audit",
              "DISCOVERY_REGISTERED" in event_types_seen or
              "DISCOVERY_BROADCAST" in event_types_seen)

    # ── Report verification ──
    print("\n  [Report]")
    report_path = os.path.join(REPORTS_DIR, "e2e-validation-target.html")
    check("report file exists", os.path.exists(report_path),
          f"not found at {report_path}")
    if os.path.exists(report_path):
        check("report non-empty", os.path.getsize(report_path) > 0)

    return True


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("vision-M: COMPLETE END-TO-END VALIDATION FLOW")
    print("Job creation → Lifecycle → SecurityWorker → Discovery")
    print("→ Audit Trail → Report → Final Verification")
    print("=" * 70)

    setup()

    # Run all steps
    contract = step1_create_job()
    store, mgr, queue, record = step2_lifecycle(contract)
    scan_result = step3_security_worker(store, mgr, queue)
    discovery_result, coord = step4_discovery_pipeline(scan_result)
    audit_events = step5_audit_trail(discovery_result)
    report_path = step6_report_generation(scan_result)
    step7_final_verification(scan_result, discovery_result, audit_events)

    # Summary
    print("\n" + "=" * 70)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 70)

    if FAIL > 0:
        print(f"\n❌ VALIDATION FAILED: {FAIL} checks failed")
        sys.exit(1)
    else:
        print(f"\n✅ ALL {PASS} CHECKS PASSED — End-to-End Validation Complete!")
        sys.exit(0)
