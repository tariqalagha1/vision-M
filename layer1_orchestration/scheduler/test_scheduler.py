#!/usr/bin/env python3
"""
Test script for Vision-M Scheduler module.

Verifies:
  1. Start the scheduler
  2. Add 3 schedules with different frequencies
  3. List schedules
  4. Verify at least one schedule fires (wait up to 5s for a short-frequency schedule)
  5. Verify a job was enqueued in JobQueue
  6. Stop the scheduler
  7. Remove a schedule
"""

import sys
import os
import time
import logging

# Ensure the vision-M package is importable
sys.path.insert(0, "/data/workspace/vision-M")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from layer1_orchestration.scheduler import VisionScheduler, HAS_APSCHEDULER, FALLBACK_MODE

# Clean slate: remove any leftover schedule files from previous runs
import os as _os
store_json = "/data/workspace/vision-M/layer1_orchestration/scheduler/schedules.json"
if _os.path.exists(store_json):
    _os.remove(store_json)
# Also clean job store
import shutil as _shutil
if _os.path.exists("/tmp/atlas_jobs"):
    _shutil.rmtree("/tmp/atlas_jobs")

print(f"\n=== Backend: {'APScheduler' if HAS_APSCHEDULER else 'heapq fallback'} ===\n")

# Create scheduler with fresh job store
sched = VisionScheduler()

PASSED = 0
FAILED = 0

def check(desc, condition):
    global PASSED, FAILED
    if condition:
        print(f"  ✅ {desc}")
        PASSED += 1
    else:
        print(f"  ❌ {desc}")
        FAILED += 1

# ── Test 1: Start the scheduler ──────────────────────────────────
print("1. Starting scheduler...")
sched.start_scheduler()
check("Scheduler is running", sched.is_running)

# ── Test 2: Add 3 schedules ──────────────────────────────────────
print("\n2. Adding schedules...")
sid1 = sched.add_schedule("test-target-1.com", "1s", "security_scan")
sid2 = sched.add_schedule("test-target-2.com", "2s", "scraping_scan")
sid3 = sched.add_schedule("test-target-3.com", "daily", "mining_scan")
check("Added 3 schedules", all([sid1, sid2, sid3]))
print(f"   SID1={sid1}")
print(f"   SID2={sid2}")
print(f"   SID3={sid3}")

# ── Test 3: List schedules ───────────────────────────────────────
print("\n3. Listing schedules...")
schedules = sched.list_schedules()
check("List returns 3 schedules", len(schedules) == 3)
for s in schedules:
    print(f"   - {s['schedule_id'][:8]}... engine={s['engine']} target={s['target']} freq={s['frequency']}")

# ── Test 4 + 5: Wait for a short-frequency schedule to fire ──────
print("\n4. Waiting for schedule to fire (up to 8s)...")
time.sleep(8)

# Check that job was enqueued by looking at the job store
from layer1_orchestration.execution.job_store import JobStore
# The scheduler uses a default store path (/tmp/atlas_jobs), let's check there
store = JobStore()
all_jobs = store.list_jobs()
print(f"   Jobs in store: {len(all_jobs)}")
for jid in all_jobs:
    rec = store.load(jid)
    if rec:
        print(f"   - {jid[:8]}... state={rec.current_state} action={rec.contract.action_type} target={rec.contract.target_asset}")

check("At least one job was enqueued", len(all_jobs) >= 1)

# Verify at least one is a scheduled job (engine matches)
scheduled_jobs = []
for jid in all_jobs:
    rec = store.load(jid)
    if rec and rec.contract.source_engine == "vision_scheduler":
        scheduled_jobs.append(rec)

check("At least one scheduled job found", len(scheduled_jobs) >= 1)

# ── Test 6: Stop the scheduler ───────────────────────────────────
print("\n6. Stopping scheduler...")
sched.stop_scheduler()
time.sleep(0.5)
check("Scheduler stopped", not sched.is_running)

# ── Test 7: Remove a schedule ────────────────────────────────────
print("\n7. Removing schedule...")
removed = sched.remove_schedule(sid2)
check("Schedule removed", removed is True)
remaining = sched.list_schedules()
check("Only 2 schedules remain", len(remaining) == 2)

# ── Summary ──────────────────────────────────────────────────────
print(f"\n{'='*60}")
if __name__ == "__main__":
    print(f"RESULTS: {PASSED} passed, {FAILED} failed")
    if FAILED == 0:
        print("OVERALL: PASS ✅")
    else:
        print("OVERALL: FAIL ❌")
    print(f"{'='*60}")
    sys.exit(0 if FAILED == 0 else 1)
