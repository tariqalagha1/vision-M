"""
vision-M: Audit Persistence Test
=================================
Tests the full audit trail: runs a complete parallel discovery and
verifies that audit.jsonl contains events from all phases with
valid JSON, required keys, and multi-gear coverage.

Audit log path: layer1_orchestration/logs/audit.jsonl
"""

import json
import os
import sys
from pathlib import Path

# ── Ensure vision-M is on path ───────────────────────────────────
_VISION_M = Path("/data/workspace/vision-M")
if str(_VISION_M) not in sys.path:
    sys.path.insert(0, str(_VISION_M))

# ── Set audit log path BEFORE importing discovery modules ─────────
AUDIT_LOG_PATH = str(_VISION_M / "layer1_orchestration" / "logs" / "audit.jsonl")
os.environ["AUDIT_LOG_PATH"] = AUDIT_LOG_PATH

from layer1_orchestration.discovery.discovery_coordinator import (
    ParallelDiscoveryCoordinator,
)

# ── Test helpers ──────────────────────────────────────────────────
PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ PASS  {name}")
    else:
        FAIL += 1
        print(f"  ❌ FAIL  {name}" + (f" — {detail}" if detail else ""))


# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Clean slate
# ═══════════════════════════════════════════════════════════════════
print("=" * 60)
print("PHASE 1: Clean up existing audit.jsonl")
print("=" * 60)

if os.path.exists(AUDIT_LOG_PATH):
    os.remove(AUDIT_LOG_PATH)
    print(f"  Removed existing {AUDIT_LOG_PATH}")
else:
    print(f"  No existing file at {AUDIT_LOG_PATH}")

os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
print(f"  Log directory ready: {os.path.dirname(AUDIT_LOG_PATH)}")

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: Run a complete discovery
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PHASE 2: Run complete discovery lifecycle")
print("=" * 60)

coord = ParallelDiscoveryCoordinator(
    mission_id="AUDIT-TEST-001",
    storage_dir="/tmp/vision_m_audit",
)

result = coord.process_discovery({
    'title': 'Audit Trail Test',
    'description': 'Testing persistent audit logging',
    'source_gear': 'security',
    'source_agent': 'audit-test-agent',
    'source_manager': 'mgr-audit',
    'discovery_types': ['API_DISCOVERY'],
    'materiality': 'high',
    'evidence_references': ['ev-audit-001'],
})

check("discovery succeeded", result.get("success") is True)
check("has phases", len(result.get("phases", [])) > 0, f"phases: {result.get('phases')}")
check("has perspectives", len(result.get("perspectives", [])) > 0)
check("has synthesis", result.get("synthesis") is not None)
check("has decision", result.get("decision") is not None)
check("event_count > 0", result.get("event_count", 0) > 0,
      f"event_count={result.get('event_count')}")

print(f"\n  Discovery ID: {result.get('discovery', {}).get('discovery_id', 'N/A')}")
print(f"  Phases: {result.get('phases')}")
print(f"  In-memory event count: {result.get('event_count')}")

# ═══════════════════════════════════════════════════════════════════
# PHASE 3: Read and validate audit.jsonl
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PHASE 3: Validate audit.jsonl")
print("=" * 60)

# --- 3a: File exists and has lines ---
file_exists = os.path.exists(AUDIT_LOG_PATH)
check("audit.jsonl exists", file_exists, AUDIT_LOG_PATH)

if not file_exists:
    print("\n  ❌ FATAL: audit.jsonl not found — cannot continue validation")
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)
    sys.exit(1)

file_size = os.path.getsize(AUDIT_LOG_PATH)
check("audit.jsonl not empty", file_size > 0, f"size={file_size} bytes")

with open(AUDIT_LOG_PATH, "r") as f:
    lines = [line.strip() for line in f if line.strip()]

line_count = len(lines)
check("has lines", line_count > 0, f"got {line_count} lines")

# --- 3b: Each line is valid JSON ---
print(f"\n  --- Validating {line_count} JSON lines ---")

events = []
json_failures = 0
for i, line_text in enumerate(lines, 1):
    try:
        event = json.loads(line_text)
        events.append(event)
    except json.JSONDecodeError as e:
        json_failures += 1
        check(f"line {i} is valid JSON", False, str(e))

check("all lines are valid JSON", json_failures == 0,
      f"{json_failures} invalid lines")

# --- 3c: Each event has required keys ---
print(f"\n  --- Checking {len(events)} events for required keys ---")

required_keys = ["event_type", "discovery_id", "timestamp"]
missing_key_count = 0
for i, event in enumerate(events, 1):
    missing = [k for k in required_keys if k not in event]
    if missing:
        missing_key_count += 1
        check(f"event {i} has required keys", False, f"missing: {missing}")

check("all events have required keys (event_type, discovery_id, timestamp)",
      missing_key_count == 0, f"{missing_key_count} events missing keys")

# --- 3d: Contains events from all phases ---
print(f"\n  --- Checking event type coverage ---")

event_types = sorted(set(e["event_type"] for e in events))

# Key event types expected across the lifecycle
expected_event_types = [
    "DISCOVERY_REGISTERED",
    "DISCOVERY_BROADCAST",
    "DISCOVERY_ACKNOWLEDGED",
    "DISCOVERY_PERSPECTIVE_GATE_PASSED",
    "DISCOVERY_SYNTHESIS_STARTED",
    "DISCOVERY_SYNTHESIS_COMPLETED",
    "NEXT_PHASE_DECISION_STARTED",
    "NEXT_PHASE_DECISION_COMPLETED",
]

for etype in expected_event_types:
    present = etype in event_types
    check(f"event type '{etype}' present", present)

# Check manager review events (confirm all 4 gears went through review)
review_event_types = [
    "PERSPECTIVE_SUBMITTED_TO_MANAGER",
    "PERSPECTIVE_MANAGER_APPROVED",
]

for etype in review_event_types:
    present = etype in event_types
    count = sum(1 for e in events if e["event_type"] == etype)
    check(f"event type '{etype}' present (x{count})", present and count >= 4,
          f"expected >=4, got {count}")

# Check perspective published events
published_event_types = [
    "SCRAPING_PERSPECTIVE_PUBLISHED",
    "MINING_PERSPECTIVE_PUBLISHED",
    "SECURITY_PERSPECTIVE_PUBLISHED",
    "EVIDENCE_PERSPECTIVE_PUBLISHED",
]

for etype in published_event_types:
    present = etype in event_types
    check(f"event type '{etype}' present", present)

# --- 3e: Events from multiple gears ---
print(f"\n  --- Checking multi-gear coverage ---")

gears_found = set()
for event in events:
    gear = event.get("gear")
    if gear:
        gears_found.add(gear)

# Also check event types for gear-specific patterns
all_gears_expected = {"scraping", "mining", "security", "evidence"}
for gear in all_gears_expected:
    # Check if gear appears in any event's "gear" field
    direct_match = gear in gears_found
    # Also check if gear appears in any event_type
    type_match = any(
        gear.upper() in e.get("event_type", "") for e in events
    )
    check(f"gear '{gear}' represented", direct_match or type_match,
          f"gear field: {direct_match}, event_type: {type_match}")

print(f"\n  Gears found in 'gear' field: {sorted(gears_found)}")

# --- 3f: All events reference the same discovery_id ---
print(f"\n  --- Checking discovery_id consistency ---")
discovery_ids = set(e["discovery_id"] for e in events)
check("all events share same discovery_id", len(discovery_ids) == 1,
      f"found {len(discovery_ids)} different IDs: {discovery_ids}")

# ═══════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("AUDIT PERSISTENCE SUMMARY")
print("=" * 60)

print(f"  Audit log: {AUDIT_LOG_PATH}")
print(f"  File size: {file_size} bytes")
print(f"  Total events persisted: {line_count}")
print(f"  In-memory event count:  {result.get('event_count')}")
print(f"  Unique event types:     {len(event_types)}")

print(f"\n  Event types found ({len(event_types)}):")
for etype in event_types:
    count = sum(1 for e in events if e["event_type"] == etype)
    print(f"    {etype:45s} x{count}")

print(f"\n  Gears represented: {sorted(gears_found)}")

print(f"\n{'=' * 60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
