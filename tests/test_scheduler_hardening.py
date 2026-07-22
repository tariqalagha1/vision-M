#!/usr/bin/env python3
"""
Test scheduler hardening fixes: H2 (fcntl.LOCK_EX) and H5 (auto-flush).

H2: Create two ScheduleStore instances pointing to the same file,
     write from both concurrently, verify no data loss.
H5: Add a schedule, verify it's immediately in the JSON file
     (not just in memory). Remove it, verify it's gone from JSON.
"""

import sys
import os
import json
import threading
import tempfile
import shutil

sys.path.insert(0, "/data/workspace/vision-M")

from layer1_orchestration.scheduler.scheduler import ScheduleStore, HAS_FCNTL

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


# ──────────────────────────────────────────────────────────────────
# H2: Concurrent writes from two ScheduleStore instances (fcntl.LOCK_EX)
# ──────────────────────────────────────────────────────────────────
print("=" * 60)
print("H2 — fcntl.LOCK_EX file locking for multi-process safety")
print("=" * 60)

print(f"\n  fcntl available: {HAS_FCNTL}")

tmpdir = tempfile.mkdtemp(prefix="sched_hardening_")
store_path = os.path.join(tmpdir, "schedules.json")

# Create two stores pointing at the same file
store_a = ScheduleStore(store_path)
store_b = ScheduleStore(store_path)

# Verify initial state
data = store_a.load_all()
check("Initial store is empty", data == {})

# Write from both stores concurrently
NUM_WRITES = 50
errors = []
writes_done = threading.Event()

def writer(store, prefix, start_idx):
    """Write many schedules from one store instance."""
    local_errors = []
    for i in range(start_idx, start_idx + NUM_WRITES):
        try:
            sid = f"{prefix}_{i:04d}"
            config = {
                "schedule_id": sid,
                "target": f"target_{i}.com",
                "frequency": "30s",
                "engine": "test_engine",
            }
            store.save(sid, config)
        except Exception as e:
            local_errors.append(f"{prefix}_{i}: {e}")
    errors.extend(local_errors)

# Launch two writer threads
t_a = threading.Thread(target=writer, args=(store_a, "A", 0))
t_b = threading.Thread(target=writer, args=(store_b, "B", NUM_WRITES))

t_a.start()
t_b.start()
t_a.join()
t_b.join()

check("No write errors during concurrent access", len(errors) == 0)

# Verify data integrity
data = store_a.load_all()
total_entries = len(data)
check(f"All {NUM_WRITES * 2} entries preserved ({total_entries} found)",
      total_entries == NUM_WRITES * 2)

# Spot-check a few entries
check("Entry A_0000 exists", "A_0000" in data)
check("Entry A_0049 exists", "A_0049" in data)
check("Entry B_0000 exists", f"B_{NUM_WRITES:04d}" in data)
check(f"Entry B_0049 exists", f"B_{NUM_WRITES + 49:04d}" in data)

# Verify content of one entry
entry = data.get("A_0000")
check("Entry A_0000 has correct target",
      entry is not None and entry.get("target") == "target_0.com")

# Cleanup
shutil.rmtree(tmpdir)

# ──────────────────────────────────────────────────────────────────
# H5: Auto-flush — verify immediate disk persistence on save/delete
# ──────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("H5 — Auto-flush on add/remove (immediate disk persistence)")
print("=" * 60)

tmpdir2 = tempfile.mkdtemp(prefix="sched_hardening_h5_")
store_path2 = os.path.join(tmpdir2, "schedules.json")

store = ScheduleStore(store_path2)

# Test save → immediate disk persistence
sid = "test_schedule_1"
config = {
    "schedule_id": sid,
    "target": "example.com",
    "frequency": "10m",
    "engine": "security_scan",
}

# Before save, file contains {} (the empty dict written by __init__)
with open(store_path2, "r") as f:
    before = json.load(f)
check("File exists before save (empty dict from init)", before == {})

# Save a schedule
store.save(sid, config)

# Immediately read the JSON file to verify it was written
with open(store_path2, "r") as f:
    after_save = json.load(f)
check("Schedule immediately persisted to JSON file after save()",
      sid in after_save)
check("Persisted config matches", after_save[sid] == config)

# Also verify it's in memory
in_memory = store.load_all()
check("Schedule also in memory", sid in in_memory)

# Test delete → immediate removal from disk
store.delete(sid)

with open(store_path2, "r") as f:
    after_delete = json.load(f)
check("Schedule immediately removed from JSON file after delete()",
      sid not in after_delete)
check("JSON file is empty after delete", after_delete == {})

# Also verify it's gone from memory
in_memory_after = store.load_all()
check("Schedule gone from memory", sid not in in_memory_after)

# Test delete of non-existent schedule (should return False)
result = store.delete("nonexistent")
check("delete() returns False for non-existent schedule", result is False)

# Cleanup
shutil.rmtree(tmpdir2)

# ──────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {PASSED} passed, {FAILED} failed")
    if FAILED == 0:
        print("OVERALL: PASS ✅")
    else:
        print("OVERALL: FAIL ❌")
    print(f"{'=' * 60}")
    sys.exit(0 if FAILED == 0 else 1)
