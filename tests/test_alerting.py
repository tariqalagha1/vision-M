"""
vision-M: Alerting Pipeline Tests
==================================
Verifies the full alerting pipeline:
  - Module imports (send_critical_alert, send_slack, send_email, send_sms)
  - Graceful degradation when no credentials configured
  - CRITICAL detection triggers alert hook
  - Non-CRITICAL does NOT trigger alert
  - alert_sent key present in SecurityWorker result
"""

import sys, os, shutil
sys.path.insert(0, '/data/workspace/vision-M')

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  ✅ PASS  {name}")
    else:
        FAIL += 1; print(f"  ❌ FAIL  {name}" + (f" — {detail}" if detail else ""))


# ═══════════════════════════════════════════════════
# TEST 1: Module Import
# ═══════════════════════════════════════════════════
print("=" * 60)
print("TEST 1: Alerts Module Import")
print("=" * 60)

try:
    from layer1_orchestration.core.alerts import (
        send_critical_alert, send_slack, send_email, send_sms
    )
    check("send_critical_alert", True)
    check("send_slack", True)
    check("send_email", True)
    check("send_sms", True)
except ImportError as e:
    check("alerts import", False, str(e))


# ═══════════════════════════════════════════════════
# TEST 2: Graceful Degradation (No Credentials)
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 2: Graceful Degradation (No Credentials)")
print("=" * 60)

try:
    result = send_critical_alert({
        'target': 'https://test.example.com',
        'risk_level': 'CRITICAL',
        'summary': 'Exposed API key detected in production',
        'findings': [{'title': 'API key in JS bundle'}],
        'timestamp': '2026-07-21T12:00:00Z',
    })
    check("returns dict", isinstance(result, dict))
    check("any_sent is False", result.get('any_sent') == False)
    check("slack key present", 'slack' in result)
    check("email key present", 'email' in result)
    check("sms key present", 'sms' in result)
    check("no crash", True)
    print(f"\n  Result: {result}")
except Exception as e:
    check("graceful degradation", False, str(e))


# ═══════════════════════════════════════════════════
# TEST 3: Slack/Email/SMS standalone functions
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 3: Standalone Channel Functions")
print("=" * 60)

try:
    r = send_slack("Test alert")
    check("send_slack returns bool", isinstance(r, bool))
    check("send_slack returns False (no config)", r == False)
except Exception as e:
    check("send_slack", False, str(e))

try:
    r = send_email("Test Subject", "Test Body")
    check("send_email returns bool", isinstance(r, bool))
    check("send_email returns False (no config)", r == False)
except Exception as e:
    check("send_email", False, str(e))

try:
    r = send_sms("+15551234567", "Test SMS")
    check("send_sms returns bool", isinstance(r, bool))
    check("send_sms returns False (no config)", r == False)
except Exception as e:
    check("send_sms", False, str(e))


# ═══════════════════════════════════════════════════
# TEST 4: CRITICAL Detection Triggers Alert
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 4: CRITICAL Detection Triggers Alert")
print("=" * 60)

from layer1_orchestration.execution.job_contract import JobRecord, JobContract, JobState
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_queue import JobQueue
from layer1_orchestration.execution.real_workers import SecurityWorker

STORE_DIR = "/tmp/vision_m_alert_e2e"
if os.path.exists(STORE_DIR):
    shutil.rmtree(STORE_DIR)
os.makedirs(STORE_DIR)

store = JobStore(STORE_DIR)
mgr = JobLifecycleManager()
queue = JobQueue(store, mgr)

# PII-rich HTML triggers CRITICAL
CRITICAL_HTML = """<html><body>
admin@corp.com | password=secret123 | api_key=sk-live-abc | 192.168.1.100
</body></html>"""

contract = JobContract.create(
    tenant_id='alert-e2e', mission_id='ALERT-001',
    parent_finding_id='f-001', parent_chain_id='c-001', hypothesis_id='h-001',
    source_engine='security', target_engine='security',
    target_asset='https://vulnerable.example.com',
    normalized_asset='vulnerable.example.com', action_type='security_scan',
    request_budget=10, authorization_reference='AUTH-ALERT-001'
)
record = JobRecord(contract=contract)
record = queue.enqueue(record)

worker = SecurityWorker('sec-alert', queue, store, mgr)
record = queue.assign(record, worker.worker_id)
record = queue.start_execution(record, worker.worker_id)
result = worker._do_work(record, {'content': CRITICAL_HTML, 'html': CRITICAL_HTML})

check("risk_level is CRITICAL", result.get('risk_level') == 'CRITICAL',
      f"Got {result.get('risk_level')}")
check("6 subtasks", len(result['completed_subtasks']) == 6)
check("alert_sent key present", 'alert_sent' in result)
check("alert_sent is dict", isinstance(result.get('alert_sent'), dict))
check("findings > 0", len(result.get('findings', [])) > 0)

print(f"\n  Risk: {result.get('risk_level')}")
print(f"  Alert sent: {result.get('alert_sent')}")
print(f"  Findings: {len(result.get('findings', []))}")


# ═══════════════════════════════════════════════════
# TEST 5: Non-CRITICAL Does NOT Trigger Alert
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 5: Non-CRITICAL Does NOT Trigger Alert")
print("=" * 60)

SAFE_HTML = "<html><body><h1>Public Page</h1><p>No sensitive data here.</p></body></html>"

store2 = JobStore("/tmp/vision_m_alert_safe")
mgr2 = JobLifecycleManager()
queue2 = JobQueue(store2, mgr2)

c2 = JobContract.create(
    tenant_id='alert-safe', mission_id='SAFE-001',
    parent_finding_id='f-002', parent_chain_id='c-002', hypothesis_id='h-002',
    source_engine='security', target_engine='security',
    target_asset='https://public.example.com',
    normalized_asset='public.example.com', action_type='security_scan',
    request_budget=10, authorization_reference='AUTH-SAFE-001'
)
r2 = JobRecord(contract=c2)
r2 = queue2.enqueue(r2)

w2 = SecurityWorker('sec-safe', queue2, store2, mgr2)
r2 = queue2.assign(r2, w2.worker_id)
r2 = queue2.start_execution(r2, w2.worker_id)
result2 = w2._do_work(r2, {'content': SAFE_HTML, 'html': SAFE_HTML})

check("risk_level is LOW", result2.get('risk_level') == 'LOW',
      f"Got {result2.get('risk_level')}")
check("alert_sent NOT present", 'alert_sent' not in result2)
check("6 subtasks", len(result2['completed_subtasks']) == 6)

print(f"\n  Risk: {result2.get('risk_level')}")
print(f"  Alert sent key present: {'alert_sent' in result2}")


# ═══════════════════════════════════════════════════
# FINAL
# ═══════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
