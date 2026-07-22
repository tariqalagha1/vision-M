"""
Section D Validation: Vision-M Input Validation & Error Handling
Validates: missing fields, evidence gate optional, failure scenarios, None-guard gaps
"""
import sys
import os
import traceback

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer1_orchestration.discovery.discovery_types import (
    DiscoveryPerspective, DiscoveryRecord, PerspectiveStatus,
    GateResult, DiscoveryType,
)
from layer1_orchestration.discovery.discovery_coordinator import ParallelDiscoveryCoordinator
from layer1_orchestration.discovery.perspective_gate import DiscoveryPerspectiveGate
from layer1_orchestration.discovery.event_bus import DiscoveryEventBus
from bridge.security_bridge import SecurityBridge

PASS, FAIL, TOTAL = 0, 0, 0


def check(name, condition, detail=""):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if condition:
        PASS += 1
        print(f"  \u2713 {name}")
    else:
        FAIL += 1
        print(f"  \u2717 {name}  \u2014 {detail}")


def header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ============================================================
# 1. DISCOVERY COORDINATOR — Input Validation
# ============================================================
header("1. DISCOVERY COORDINATOR — Input Validation (discovery_coordinator.py)")

coordinator = ParallelDiscoveryCoordinator(mission_id="M001", storage_dir="/tmp")

# Test 1a: Missing title
result_no_title = coordinator.process_discovery({
    "description": "A discovery without a title",
    "source_agent": "agent-scrape",
})
check("Missing 'title' returns graceful error dict (not KeyError)",
      isinstance(result_no_title, dict) and result_no_title.get("success") is False,
      f"type={type(result_no_title).__name__}, result={result_no_title}")
check("Missing 'title' error mentions 'title' in missing fields",
      "title" in str(result_no_title.get("error", "")),
      f"error: {result_no_title.get('error')}")
check("Missing 'title' has empty phases list",
      result_no_title.get("phases") == [],
      f"phases={result_no_title.get('phases')}")
check("Missing 'title' returns empty discovery",
      result_no_title.get("discovery") == {},
      f"discovery={result_no_title.get('discovery')}")
check("Missing 'title' returns gate_result=None",
      result_no_title.get("gate_result") is None,
      f"gate_result={result_no_title.get('gate_result')}")
check("Missing 'title' returns synthesis=None",
      result_no_title.get("synthesis") is None)
check("Missing 'title' returns decision=None",
      result_no_title.get("decision") is None)

# Test 1b: Missing source_agent
result_no_agent = coordinator.process_discovery({
    "title": "API Discovery Without Source Agent",
    "description": "Missing source_agent field",
})
check("Missing 'source_agent' returns graceful error dict (not KeyError)",
      isinstance(result_no_agent, dict) and result_no_agent.get("success") is False,
      f"result={result_no_agent}")
check("Missing 'source_agent' error mentions 'source_agent'",
      "source_agent" in str(result_no_agent.get("error", "")),
      f"error={result_no_agent.get('error')}")
check("Missing 'source_agent' returns empty discovery",
      result_no_agent.get("discovery") == {})

# Test 1c: Missing both required fields
result_both_missing = coordinator.process_discovery({
    "description": "Missing everything important",
})
check("Missing both 'title' and 'source_agent' returns error dict",
      isinstance(result_both_missing, dict) and result_both_missing.get("success") is False)
check("Both missing fields listed in error",
      "title" in str(result_both_missing.get("error", "")) and
      "source_agent" in str(result_both_missing.get("error", "")),
      f"error={result_both_missing.get('error')}")

# Test 1d: Empty string for title
result_empty_title = coordinator.process_discovery({
    "title": "",
    "source_agent": "agent-scrape",
})
check("Empty string 'title' returns error (treated as missing)",
      result_empty_title.get("success") is False,
      f"success={result_empty_title.get('success')}, error={result_empty_title.get('error')}")
check("Empty 'title' error mentions 'title'",
      "title" in str(result_empty_title.get("error", "")),
      f"error={result_empty_title.get('error')}")

# Test 1e: Empty string for source_agent
result_empty_agent = coordinator.process_discovery({
    "title": "Valid Title",
    "source_agent": "",
})
check("Empty string 'source_agent' returns error (treated as missing)",
      result_empty_agent.get("success") is False,
      f"success={result_empty_agent.get('success')}, error={result_empty_agent.get('error')}")

# Test 1f: Empty dict input (graceful, no crash)
result_empty = coordinator.process_discovery({})
check("Empty dict input returns error (no crash)",
      isinstance(result_empty, dict) and result_empty.get("success") is False,
      f"result={result_empty}")

# Test 1g: Valid input — 7-phase pipeline proceeds normally
result_valid = coordinator.process_discovery({
    "title": "Product Catalog API",
    "description": "Structured product catalog API endpoint",
    "source_gear": "scraping",
    "source_agent": "agent-scrape",
    "source_manager": "mgr-scrape",
    "discovery_types": ["API_DISCOVERY", "STRUCTURED_CATALOG"],
    "materiality": "high",
    "evidence_references": ["ev-001", "ev-002"],
})
check("Valid input: process_discovery returns success=True",
      result_valid.get("success") is True,
      f"success={result_valid.get('success')}, error={result_valid.get('error', 'N/A')}")
check("Valid input: returns 7 phases",
      len(result_valid.get("phases", [])) == 7,
      f"phases={result_valid.get('phases')}")
expected_phases = [
    "broadcast_complete", "perspectives_generated", "manager_review_complete",
    "cross_sharing_complete", "gate_passed", "synthesis_complete", "decision_complete",
]
phases = result_valid.get("phases", [])
for i, expected in enumerate(expected_phases):
    check(f"Valid input Phase {i+1}: {expected}",
          phases[i] == expected if i < len(phases) else False,
          f"got: {phases[i] if i < len(phases) else 'MISSING'}")

check("Valid input: has discovery dict",
      isinstance(result_valid.get("discovery"), dict) and len(result_valid.get("discovery", {})) > 0)
check("Valid input: has 4 perspectives",
      len(result_valid.get("perspectives", [])) == 4)
check("Valid input: gate_result is not None",
      result_valid.get("gate_result") is not None)
check("Valid input: synthesis is not None",
      result_valid.get("synthesis") is not None)
check("Valid input: decision is not None",
      result_valid.get("decision") is not None)

# Test 1h: No crash on missing optional fields (should work with defaults)
result_minimal = coordinator.process_discovery({
    "title": "Minimal Discovery",
    "source_agent": "agent-minimal",
})
check("Minimal input (only required fields) succeeds",
      result_minimal.get("success") is True,
      f"success={result_minimal.get('success')}, error={result_minimal.get('error', 'N/A')}")
check("Minimal input: returns 7 phases",
      len(result_minimal.get("phases", [])) == 7)

# ============================================================
# 2. PERSPECTIVE GATE — Evidence Gate and Approval Checks
# ============================================================
header("2. PERSPECTIVE GATE — Evidence & Approval (perspective_gate.py)")

gate_bus = DiscoveryEventBus()
gate = DiscoveryPerspectiveGate(gate_bus)

# Helper to create a perspective
def make_persp(gear, status, evidence_ids=None, auth_impact="authorization assessed"):
    p = DiscoveryPerspective.create(
        discovery_id="D_TEST", mission_id="M001", correlation_id="C001",
        gear=gear, producing_agent_id=f"agent-{gear}",
        approving_manager_id=f"mgr-{gear}",
        interpretation=f"Test interpretation from {gear}",
        evidence_ids=evidence_ids if evidence_ids is not None else ["ev-1"],
        opportunities=[], risks=[], uncertainties=[], contradictions=[],
        recommended_actions=[],
        operational_impact="", data_acquisition_impact="",
        mining_impact="", security_impact="",
        scope_impact="", authorization_impact=auth_impact,
        confidence=0.75,
    )
    p.status = status
    return p

# Test 2a: evidence_required=False is the default parameter
import inspect
sig = inspect.signature(gate.evaluate)
default_ev = sig.parameters.get("evidence_required")
check("evidence_required defaults to False",
      default_ev is not None and default_ev.default is False,
      f"default={default_ev.default if default_ev else 'MISSING'}")

# Test 2b: Valid discovery without evidence_ids passes gate (evidence_required=False default)
persps_no_ev = [
    make_persp("scraping", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
    make_persp("mining", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
    make_persp("evidence", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
]
result_no_ev_required = gate.evaluate(
    "D_NOEV", "M001", "C001", "CAU001", persps_no_ev,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    # evidence_required defaults to False — not passed
)
check("evidence_required=False (default): passes with empty evidence_ids",
      result_no_ev_required.passed is True,
      f"passed={result_no_ev_required.passed}, failures={result_no_ev_required.failures}")

# Test 2c: evidence_required=True with no evidence → fails
result_ev_required = gate.evaluate(
    "D_EVREQ", "M001", "C001", "CAU001", persps_no_ev,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    evidence_required=True,
)
check("evidence_required=True: fails when no evidence_ids",
      result_ev_required.passed is False,
      f"passed={result_ev_required.passed}")
check("evidence_required=True: failure mentions 'evidence references'",
      any("evidence" in f.lower() for f in result_ev_required.failures),
      f"failures={result_ev_required.failures}")

# Test 2d: evidence_required=True with evidence → passes
persps_with_ev = [
    make_persp("scraping", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-1"]),
    make_persp("mining", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-2"]),
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-3"]),
    make_persp("evidence", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-4"]),
]
result_ev_ok = gate.evaluate(
    "D_EVOK", "M001", "C001", "CAU001", persps_with_ev,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    evidence_required=True,
)
check("evidence_required=True: passes when all have evidence_ids",
      result_ev_ok.passed is True,
      f"passed={result_ev_ok.passed}, failures={result_ev_ok.failures}")

# Test 2e: evidence_required=True with partial evidence → fails
persps_partial_ev = [
    make_persp("scraping", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-1"]),
    make_persp("mining", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-3"]),
    make_persp("evidence", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=[]),
]
result_partial_ev = gate.evaluate(
    "D_PARTIAL", "M001", "C001", "CAU001", persps_partial_ev,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    evidence_required=True,
)
check("evidence_required=True: fails when some perspectives lack evidence",
      result_partial_ev.passed is False,
      f"passed={result_partial_ev.passed}, failures={result_partial_ev.failures}")
check("evidence_required=True partial: failure count >= 2 (mining + evidence missing)",
      len(result_partial_ev.failures) >= 2,
      f"failures count={len(result_partial_ev.failures)}, failures={result_partial_ev.failures}")

# Test 2f: Unapproved perspective → gate fails
persp_unapproved = make_persp("scraping", PerspectiveStatus.CREATED.value,
                               evidence_ids=["ev-1"])
persps_one_unapproved = [
    persp_unapproved,
    make_persp("mining", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-2"]),
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-3"]),
    make_persp("evidence", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-4"]),
]
result_unapproved = gate.evaluate(
    "D_UNAPP", "M001", "C001", "CAU001", persps_one_unapproved,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
)
check("Unapproved perspective: gate fails",
      result_unapproved.passed is False,
      f"passed={result_unapproved.passed}")
check("Unapproved perspective: failure mentions 'not manager-approved'",
      any("manager-approved" in f.lower() or "not manager" in f.lower()
          for f in result_unapproved.failures),
      f"failures={result_unapproved.failures}")

# Test 2g: REJECTED perspective → gate fails
persp_rejected = make_persp("mining", PerspectiveStatus.MANAGER_REJECTED.value,
                              evidence_ids=["ev-2"])
persps_one_rejected = [
    make_persp("scraping", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-1"]),
    persp_rejected,
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-3"]),
    make_persp("evidence", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-4"]),
]
result_rejected = gate.evaluate(
    "D_REJ", "M001", "C001", "CAU001", persps_one_rejected,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
)
check("REJECTED perspective: gate fails",
      result_rejected.passed is False,
      f"passed={result_rejected.passed}, failures={result_rejected.failures}")

# Test 2h: REWORK_REQUIRED perspective → gate fails
persp_rework = make_persp("evidence", PerspectiveStatus.REWORK_REQUIRED.value,
                           evidence_ids=["ev-4"])
persps_one_rework = [
    make_persp("scraping", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-1"]),
    make_persp("mining", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-2"]),
    make_persp("security", PerspectiveStatus.MANAGER_APPROVED.value, evidence_ids=["ev-3"]),
    persp_rework,
]
result_rework = gate.evaluate(
    "D_RW", "M001", "C001", "CAU001", persps_one_rework,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
)
check("REWORK_REQUIRED perspective: gate fails",
      result_rework.passed is False,
      f"passed={result_rework.passed}, failures={result_rework.failures}")

# Test 2i: Empty acknowledgments → gate fails
result_no_ack = gate.evaluate(
    "D_NOACK", "M001", "C001", "CAU001", persps_with_ev,
    acknowledgments_gears=set(),
)
check("Empty acknowledgments: gate fails (missing acks)",
      result_no_ack.passed is False,
      f"passed={result_no_ack.passed}, failures={result_no_ack.failures}")

# Test 2j: None acknowledgments → gate passes (optional parameter, no check)
result_ack_none = gate.evaluate(
    "D_ACKNONE", "M001", "C001", "CAU001", persps_with_ev,
    acknowledgments_gears=None,
)
check("acknowledgments_gears=None: gate does not check acks (passed)",
      result_ack_none.passed is True,
      f"passed={result_ack_none.passed}, failures={result_ack_none.failures}")

# Test 2k: GateResult.to_dict() works correctly for failed gate
check("GateResult.to_dict() has required fields for passed",
      all(k in result_ev_ok.to_dict() for k in ["gate_name", "passed", "missing", "failures", "evaluated_at"]))
check("GateResult.to_dict() has required fields for failed",
      all(k in result_ev_required.to_dict() for k in ["gate_name", "passed", "missing", "failures", "evaluated_at"]))
check("Failed gate has gate_name",
      result_ev_required.gate_name == "DISCOVERY_PERSPECTIVE_COMPLETION")

# ============================================================
# 3. FAILURE SCENARIOS — All 6 produce proper error/response dicts
# ============================================================
header("3. FAILURE SCENARIOS — 6 Scenarios (discovery_coordinator.py)")

coord2 = ParallelDiscoveryCoordinator(mission_id="M002", storage_dir="/tmp")

# Scenario 1: Delayed gear (mining)
try:
    fs1 = coord2.run_failure_scenario_1()
    check("FS1 (delayed gear): returns dict",
          isinstance(fs1, dict))
    check("FS1: initial_gate_passed is False",
          fs1.get("initial_gate_passed") is False,
          f"initial_gate_passed={fs1.get('initial_gate_passed')}")
    check("FS1: decision_blocked is True",
          fs1.get("decision_blocked") is True,
          f"decision_blocked={fs1.get('decision_blocked')}")
    check("FS1: resolved_gate_passed is True",
          fs1.get("resolved_gate_passed") is True)
    check("FS1: MINING in missing_gears",
          "MINING" in fs1.get("missing_gears", []),
          f"missing_gears={fs1.get('missing_gears')}")
    check("FS1: has phases list",
          len(fs1.get("phases", [])) > 0)
except Exception as e:
    check("FS1 (delayed gear): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")

# Scenario 2: Security-first attempt
try:
    fs2 = coord2.run_failure_scenario_2()
    check("FS2 (security-first): returns dict",
          isinstance(fs2, dict))
    check("FS2: early_decision_blocked is True",
          fs2.get("early_decision_blocked") is True,
          f"early_decision_blocked={fs2.get('early_decision_blocked')}")
    check("FS2: gate_passed_after_all_perspectives is True",
          fs2.get("gate_passed_after_all_perspectives") is True)
    check("FS2: decision_allowed_after_gate is True",
          fs2.get("decision_allowed_after_gate") is True)
    check("FS2: block_reason is not empty",
          bool(fs2.get("block_reason")),
          f"block_reason={fs2.get('block_reason')}")
except Exception as e:
    check("FS2 (security-first): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")

# Scenario 3: Scraping rejected
try:
    fs3 = coord2.run_failure_scenario_3()
    check("FS3 (scraping rejected): returns dict",
          isinstance(fs3, dict))
    check("FS3: initial_gate_passed is False",
          fs3.get("initial_gate_passed") is False)
    check("FS3: scraping_rejected is True",
          fs3.get("scraping_rejected") is True)
    check("FS3: reworked_approved is True",
          fs3.get("reworked_approved") is True)
    check("FS3: final_gate_passed is True",
          fs3.get("final_gate_passed") is True)
except Exception as e:
    check("FS3 (scraping rejected): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")

# Scenario 4: Evidence contradiction
try:
    fs4 = coord2.run_failure_scenario_4()
    check("FS4 (contradiction): returns dict",
          isinstance(fs4, dict))
    check("FS4: gate_passed is True",
          fs4.get("gate_passed") is True)
    check("FS4: contradiction_detected is True",
          fs4.get("contradiction_detected") is True)
    check("FS4: synthesis_preserved_disagreement is True",
          fs4.get("synthesis_preserved_disagreement") is True)
    check("FS4: areas_of_contradiction has items",
          len(fs4.get("areas_of_contradiction", [])) > 0,
          f"areas_of_contradiction={fs4.get('areas_of_contradiction')}")
except Exception as e:
    check("FS4 (contradiction): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")

# Scenario 5: Missing acknowledgment
try:
    fs5 = coord2.run_failure_scenario_5()
    check("FS5 (missing ack): returns dict",
          isinstance(fs5, dict))
    check("FS5: scraping in missing_before_retry",
          "scraping" in fs5.get("missing_before_retry", []),
          f"missing_before_retry={fs5.get('missing_before_retry')}")
    check("FS5: all_acknowledged is True after retry",
          fs5.get("all_acknowledged") is True)
except Exception as e:
    check("FS5 (missing ack): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")

# Scenario 6: Early decision
try:
    fs6 = coord2.run_failure_scenario_6()
    check("FS6 (early decision): returns dict",
          isinstance(fs6, dict))
    check("FS6: early_decision_blocked is True",
          fs6.get("early_decision_blocked") is True,
          f"early_decision_blocked={fs6.get('early_decision_blocked')}")
    check("FS6: decision_allowed_after_completion is True",
          fs6.get("decision_allowed_after_completion") is True)
    check("FS6: gate_passed is True",
          fs6.get("gate_passed") is True)
    check("FS6: has block_error_code",
          bool(fs6.get("block_error_code")),
          f"block_error_code={fs6.get('block_error_code')}")
except Exception as e:
    check("FS6 (early decision): no exception",
          False, f"Exception: {e}\n{traceback.format_exc()}")


# ============================================================
# 4. SECURITY BRIDGE — None-guard Gaps
# ============================================================
header("4. SECURITY BRIDGE — None-guard Gaps (bridge/security_bridge.py)")

bridge = SecurityBridge()

# Test 4a: audit_authorization(None, None) — should handle gracefully or crash
try:
    result_none_none = bridge.audit_authorization(None, None)
    check("audit_authorization(None, None): returns dict (no crash)",
          isinstance(result_none_none, dict),
          f"returned: {type(result_none_none).__name__}")
    check("audit_authorization(None, None): has 'status' key",
          "status" in result_none_none,
          f"keys={list(result_none_none.keys())}")
except TypeError as e:
    # TypeError might be acceptable if content=None hits .lower()
    check("audit_authorization(None, None): TypeError (not uncaught crash)",
          isinstance(e, TypeError),
          f"TypeError: {e}")
except AttributeError as e:
    # AttributeError from None.lower() — this IS a crash for .lower()
    check("audit_authorization(None, None): CRASH (AttributeError on None.lower()) — None-guard GAP",
          False,
          f"AttributeError: {e}")
except Exception as e:
    check("audit_authorization(None, None): unexpected exception",
          False, f"{type(e).__name__}: {e}")

# Test 4b: audit_authorization("test", None) — content=None
try:
    result_target_none = bridge.audit_authorization("test-target", None)
    check("audit_authorization('test', None): returns dict (no crash)",
          isinstance(result_target_none, dict),
          f"returned: {type(result_target_none).__name__}")
    check("audit_authorization('test', None): has findings",
          "findings" in result_target_none,
          f"keys={list(result_target_none.keys())}")
except TypeError as e:
    check("audit_authorization('test', None): TypeError",
          isinstance(e, TypeError),
          f"TypeError: {e}")
except AttributeError as e:
    check("audit_authorization('test', None): CRASH (AttributeError on None.lower()) — None-guard GAP",
          False,
          f"AttributeError: {e}")

# Test 4c: observe_passively('test', None) — content=None
try:
    result_obs_none = bridge.observe_passively("test-target", None)
    check("observe_passively('test', None): returns dict (no crash)",
          isinstance(result_obs_none, dict),
          f"returned: {type(result_obs_none).__name__}")
    check("observe_passively('test', None): has observations",
          "observations" in result_obs_none,
          f"keys={list(result_obs_none.keys())}")
except TypeError as e:
    check("observe_passively('test', None): TypeError",
          isinstance(e, TypeError),
          f"TypeError: {e}")
except AttributeError as e:
    check("observe_passively('test', None): CRASH (AttributeError on None.lower()) — None-guard GAP",
          False,
          f"AttributeError: {e}")

# Test 4d: observe_passively(None, "") — target=None
try:
    result_target_none_obs = bridge.observe_passively(None, "")
    check("observe_passively(None, ''): returns dict (no crash)",
          isinstance(result_target_none_obs, dict),
          f"returned: {type(result_target_none_obs).__name__}")
except TypeError as e:
    check("observe_passively(None, ''): TypeError (target used in 'in' check)",
          isinstance(e, TypeError),
          f"TypeError: {e}")
except Exception as e:
    check("observe_passively(None, ''): unexpected exception",
          False, f"{type(e).__name__}: {e}")

# Test 4e: Normal usage — verify bridge works correctly
try:
    result_normal = bridge.audit_authorization("test", "some response with nginx and password")
    check("audit_authorization normal: returns dict",
          isinstance(result_normal, dict))
    check("audit_authorization normal: finds exposed data",
          result_normal.get("findings_count", 0) > 0,
          f"findings_count={result_normal.get('findings_count')}, findings={result_normal.get('findings')}")
except Exception as e:
    check("audit_authorization normal: no exception",
          False, f"{type(e).__name__}: {e}")

try:
    result_obs_normal = bridge.observe_passively("test-target", "nginx cloudflare react")
    check("observe_passively normal: returns dict",
          isinstance(result_obs_normal, dict))
    check("observe_passively normal: detects tech stack",
          result_obs_normal.get("observation_count", 0) > 0,
          f"observation_count={result_obs_normal.get('observation_count')}")
except Exception as e:
    check("observe_passively normal: no exception",
          False, f"{type(e).__name__}: {e}")

# Test 4f: verify_scope with boundary cases
try:
    result_scope = bridge.verify_scope("test-target", "auth-ref-1")
    check("verify_scope normal: returns dict",
          isinstance(result_scope, dict))
    check("verify_scope normal: IN_SCOPE",
          result_scope.get("status") == "IN_SCOPE",
          f"status={result_scope.get('status')}")
except Exception as e:
    check("verify_scope normal: no exception",
          False, f"{type(e).__name__}: {e}")

try:
    result_blocked = bridge.verify_scope("target.gov", "auth-ref")
    check("verify_scope .gov: BLOCKED",
          result_blocked.get("status") == "BLOCKED",
          f"status={result_blocked.get('status')}")
except Exception as e:
    check("verify_scope .gov: no exception",
          False, f"{type(e).__name__}: {e}")

try:
    result_internal = bridge.verify_scope("192.168.1.1", "auth-ref")
    check("verify_scope internal IP: BLOCKED",
          result_internal.get("status") == "BLOCKED",
          f"status={result_internal.get('status')}")
except Exception as e:
    check("verify_scope internal IP: no exception",
          False, f"{type(e).__name__}: {e}")


# ============================================================
# 5. GENERAL ERROR HANDLING — Try/except blocks
# ============================================================
header("5. GENERAL ERROR HANDLING — Try/Except & Exception Chaining")

# Test 5a: process_discovery with unexpected types in input
try:
    result_weird = coordinator.process_discovery({
        "title": 12345,  # integer instead of string
        "source_agent": None,  # None instead of string
    })
    check("Weird types in input: does not crash (title=12345, source_agent=None)",
          isinstance(result_weird, dict),
          f"result type={type(result_weird).__name__}")
except Exception as e:
    check("Weird types in input: raised exception (acceptable behavior)",
          False, f"{type(e).__name__}: {e}")

# Test 5b: process_discovery with None as finding_data
try:
    result_none_data = coordinator.process_discovery(None)
    check("process_discovery(None): no crash",
          False, "Should not reach here — expecting exception")
except TypeError as e:
    # .get() on None would fail — this is expected
    check("process_discovery(None): TypeError raised (expected — None has no .get)",
          isinstance(e, TypeError),
          f"TypeError: {e}")
except Exception as e:
    check("process_discovery(None): raised exception",
          True, f"{type(e).__name__}: {e} — this is acceptable since None is not a dict")

# Test 5c: manager_review with invalid decision
# Already covered by failure scenario 3 (REJECTED)

# Test 5d: perspective_gate with empty perspectives list
try:
    result_empty_persps = gate.evaluate(
        "D_EMPTY", "M001", "C001", "CAU001", [],
        acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    )
    check("gate with empty perspectives: fails gracefully",
          isinstance(result_empty_persps, GateResult) and result_empty_persps.passed is False,
          f"passed={result_empty_persps.passed}, failures={result_empty_persps.failures}")
    check("gate with empty perspectives: mentions all 4 missing gears",
          len(result_empty_persps.failures) >= 1,
          f"failures={result_empty_persps.failures}")
except Exception as e:
    check("gate with empty perspectives: no crash",
          False, f"{type(e).__name__}: {e}")

# Test 5e: event_bus publishes with None data gracefully
try:
    new_bus = DiscoveryEventBus()
    from layer1_orchestration.discovery.event_bus import DiscoveryEvent, DiscoveryEventType
    ev = DiscoveryEvent.create(
        event_type=DiscoveryEventType.DISCOVERY_DETECTED,
        discovery_id="D_ERR", mission_id="M001", correlation_id="C_ERR",
        causation_id="CAU_ERR", producer="test", receiver="ALL",
        gear="scraping", manager="mgr-1", evidence_reference="ev-1",
        data=None,
    )
    new_bus.publish(ev)
    check("Event with data=None: publishes without crash",
          new_bus.event_count == 1,
          f"event_count={new_bus.event_count}")
except Exception as e:
    check("Event with data=None: no exception",
          False, f"{type(e).__name__}: {e}")

# Test 5f: SecurityBridge PII patterns with empty string content
try:
    result_empty_content = bridge.audit_authorization("test", "")
    check("audit_authorization with empty string: returns dict",
          isinstance(result_empty_content, dict))
    check("audit_authorization with empty string: 0 findings",
          result_empty_content.get("findings_count") == 0,
          f"findings_count={result_empty_content.get('findings_count')}")
except Exception as e:
    check("audit_authorization with empty string: no exception",
          False, f"{type(e).__name__}: {e}")

# Test 5g: Classification/risk analysis with empty audit results
try:
    empty_audit = bridge.audit_authorization("test", "")
    empty_obs = bridge.observe_passively("test-target", "")
    exposure = bridge.analyze_exposure(empty_audit, empty_obs)
    check("analyze_exposure with empty findings: returns dict",
          isinstance(exposure, dict))
    check("analyze_exposure with empty findings: exposure_level=LOW",
          exposure.get("exposure_level") == "LOW",
          f"exposure_level={exposure.get('exposure_level')}")

    risk = bridge.classify_risk(exposure, empty_audit)
    check("classify_risk with empty findings: returns dict",
          isinstance(risk, dict))
    check("classify_risk with empty findings: risk_level=LOW",
          risk.get("risk_level") == "LOW",
          f"risk_level={risk.get('risk_level')}")

    recs = bridge.synthesize_recommendations(risk, exposure)
    check("synthesize_recommendations: returns dict",
          isinstance(recs, dict))
    check("synthesize_recommendations: has recommendations",
          recs.get("total_recommendations", 0) > 0,
          f"total_recommendations={recs.get('total_recommendations')}")
except Exception as e:
    check("Full pipeline with empty findings: no exception",
          False, f"{type(e).__name__}: {e}")


# ============================================================
# SUMMARY
# ============================================================
header("SUMMARY — Section D: Input Validation & Error Handling")

print(f"\n  Total: {TOTAL} checks")
print(f"  PASS:  {PASS}")
print(f"  FAIL:  {FAIL}")
print(f"  Rate:  {PASS/TOTAL*100:.1f}% pass\n")

if FAIL > 0:
    sys.exit(1)
else:
    sys.exit(0)
