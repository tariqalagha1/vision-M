"""
Section A Validation: Vision-M Core Orchestration
Validates: 4 gears, 7 phases, shared register, event bus, gate, cross-sharing, synthesis, broadcast
"""
import sys
import os

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer1_orchestration.discovery.event_bus import DiscoveryEventBus, DiscoveryEvent, DiscoveryEventType
from layer1_orchestration.discovery.discovery_types import (DiscoveryPerspective, DiscoveryRecord, PerspectiveStatus,
                                                            SynthesisResult, ManagementDecision, GateResult,
                                                            AcknowledgmentRecord, DecisionType)
from layer1_orchestration.discovery.gear_engines import (GearEngineRegistry, ScrapingGearEngine, MiningGearEngine,
                                                         SecurityGearEngine, EvidenceGearEngine, BaseGearEngine)
from layer1_orchestration.discovery.discovery_register import DiscoveryRegister
from layer1_orchestration.discovery.discovery_broadcast import DiscoveryBroadcast
from layer1_orchestration.discovery.perspective_gate import DiscoveryPerspectiveGate
from layer1_orchestration.discovery.cross_sharing import CrossSharingEngine
from layer1_orchestration.discovery.evidence_synthesis import EvidenceSynthesisEngine
from layer1_orchestration.discovery.discovery_coordinator import ParallelDiscoveryCoordinator

PASS, FAIL, TOTAL = 0, 0, 0


def check(name, condition, detail=""):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if condition:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  — {detail}")


def header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ==================== 1. GEAR ENGINES ====================
header("1. GEAR ENGINES (gear_engines.py)")

registry = GearEngineRegistry()
engines = registry.get_all_engines()

check("4 engines registered (scraping, mining, security, evidence)",
      set(engines.keys()) == {"scraping", "mining", "security", "evidence"})

check("ScrapingGearEngine extends BaseGearEngine",
      isinstance(engines["scraping"], BaseGearEngine))

check("MiningGearEngine extends BaseGearEngine",
      isinstance(engines["mining"], BaseGearEngine))

check("SecurityGearEngine extends BaseGearEngine",
      isinstance(engines["security"], BaseGearEngine))

check("EvidenceGearEngine extends BaseGearEngine",
      isinstance(engines["evidence"], BaseGearEngine))

# Create a test discovery
test_disc = DiscoveryRecord.create(
    mission_id="M001", source_gear="scraping", source_agent_id="agent-1",
    source_manager_id="mgr-1", discovery_types=["API_DISCOVERY", "STRUCTURED_CATALOG"],
    materiality="high", evidence_references=["ev-1", "ev-2"],
    title="Test Discovery", description="Test"
)

# Test each engine produces a DiscoveryPerspective
for gear_name, engine in engines.items():
    persp = engine.analyze(test_disc, f"agent-{gear_name}")
    check(f"{gear_name} engine produces DiscoveryPerspective",
          isinstance(persp, DiscoveryPerspective),
          f"got {type(persp).__name__}")
    check(f"{gear_name} gear_name matches ({engine.gear_name})",
          engine.gear_name == gear_name)
    check(f"{gear_name} perspective has interpretation",
          len(persp.interpretation) > 50,
          f"interpretation length: {len(persp.interpretation)}")
    check(f"{gear_name} perspective has confidence",
          persp.confidence > 0 and persp.confidence <= 1.0,
          f"confidence: {persp.confidence}")

# Test get_engine for each gear
for gear_name in ["scraping", "mining", "security", "evidence"]:
    engine = registry.get_engine(gear_name)
    check(f"get_engine('{gear_name}') returns correct engine",
          engine.gear_name == gear_name)

# Test unknown gear raises
try:
    registry.get_engine("nonexistent")
    check("get_engine('nonexistent') raises ValueError", False, "no exception raised")
except ValueError:
    check("get_engine('nonexistent') raises ValueError", True)

# Test required_gears property
check("required_gears returns 4 sorted names",
      registry.required_gears == ["evidence", "mining", "scraping", "security"])


# ==================== 2. DISCOVERY COORDINATOR ====================
header("2. DISCOVERY COORDINATOR (discovery_coordinator.py)")

coordinator = ParallelDiscoveryCoordinator(mission_id="M001", storage_dir="/tmp")

# Verify REQUIRED_GEARS
check("coordinator REQUIRED_GEARS = ['scraping','mining','security','evidence']",
      coordinator.REQUIRED_GEARS == ["scraping", "mining", "security", "evidence"])

# Test the main process_discovery() 7-phase pipeline
result = coordinator.process_discovery({
    "title": "Product Catalog API",
    "description": "Structured product catalog API discovered",
    "source_gear": "scraping",
    "source_agent": "agent-scrape",
    "source_manager": "mgr-scrape",
    "discovery_types": ["API_DISCOVERY", "STRUCTURED_CATALOG"],
    "materiality": "high",
    "evidence_references": ["ev-001", "ev-002"],
})

check("process_discovery returns success=True",
      result.get("success") is True,
      f"success={result.get('success')}, error={result.get('error', 'N/A')}")

check("process_discovery returns 7 phases",
      len(result.get("phases", [])) == 7,
      f"phases: {result.get('phases')}")

# Check each phase present
phases = result.get("phases", [])
expected_phases = [
    "broadcast_complete",
    "perspectives_generated",
    "manager_review_complete",
    "cross_sharing_complete",
    "gate_passed",
    "synthesis_complete",
    "decision_complete",
]
for i, expected in enumerate(expected_phases):
    check(f"Phase {i+1}: {expected}",
          phases[i] == expected if i < len(phases) else False,
          f"got: {phases[i] if i < len(phases) else 'MISSING'}")

check("result has discovery",
      "discovery" in result and result["discovery"] is not None)

check("result has perspectives",
      len(result.get("perspectives", [])) == 4,
      f"got {len(result.get('perspectives', []))} perspectives")

check("result has gate_result",
      result.get("gate_result") is not None)

check("result has synthesis",
      result.get("synthesis") is not None)

check("result has decision",
      result.get("decision") is not None)

check("event_count > 0",
      result.get("event_count", 0) > 0,
      f"event_count={result.get('event_count')}")

# Test missing required fields
bad_result = coordinator.process_discovery({"description": "Missing title and source_agent"})
check("process_discovery fails on missing required fields",
      bad_result.get("success") is False,
      f"success={bad_result.get('success')}")
check("error message mentions missing fields",
      "Missing required fields" in bad_result.get("error", ""),
      f"error: {bad_result.get('error')}")

# Test noon demonstration
demo = coordinator.run_noon_demonstration()
check("run_noon_demonstration returns success=True",
      demo.get("success") is True)

# Test failure scenario 1: delayed mining
fs1 = coordinator.run_failure_scenario_1()
check("failure_scenario_1: initial gate fails",
      fs1.get("initial_gate_passed") is False)
check("failure_scenario_1: decision blocked",
      fs1.get("decision_blocked") is True)
check("failure_scenario_1: resolved gate passes",
      fs1.get("resolved_gate_passed") is True)
check("failure_scenario_1: mining is in missing_gears",
      "MINING" in fs1.get("missing_gears", []),
      f"missing_gears={fs1.get('missing_gears')}")

# Test failure scenario 2: security first
fs2 = coordinator.run_failure_scenario_2()
check("failure_scenario_2: early decision blocked",
      fs2.get("early_decision_blocked") is True)
check("failure_scenario_2: gate passes after all perspectives",
      fs2.get("gate_passed_after_all_perspectives") is True)
check("failure_scenario_2: decision allowed after gate",
      fs2.get("decision_allowed_after_gate") is True)

# Test failure scenario 3: scraping rejected
fs3 = coordinator.run_failure_scenario_3()
check("failure_scenario_3: initial gate fails",
      fs3.get("initial_gate_passed") is False)
check("failure_scenario_3: scraping rejected",
      fs3.get("scraping_rejected") is True)
check("failure_scenario_3: reworked approved",
      fs3.get("reworked_approved") is True)
check("failure_scenario_3: final gate passes",
      fs3.get("final_gate_passed") is True)

# Test failure scenario 4: evidence contradiction
fs4 = coordinator.run_failure_scenario_4()
check("failure_scenario_4: gate passes despite contradiction",
      fs4.get("gate_passed") is True)
check("failure_scenario_4: contradiction detected",
      fs4.get("contradiction_detected") is True)
check("failure_scenario_4: synthesis preserves disagreement",
      fs4.get("synthesis_preserved_disagreement") is True)

# Test failure scenario 5: missing acknowledgment
fs5 = coordinator.run_failure_scenario_5()
check("failure_scenario_5: scraping missing before retry",
      "scraping" in fs5.get("missing_before_retry", []))
check("failure_scenario_5: all acknowledged after retry",
      fs5.get("all_acknowledged") is True)

# Test failure scenario 6: early decision
fs6 = coordinator.run_failure_scenario_6()
check("failure_scenario_6: early decision blocked",
      fs6.get("early_decision_blocked") is True)
check("failure_scenario_6: decision allowed after completion",
      fs6.get("decision_allowed_after_completion") is True)
check("failure_scenario_6: gate passes",
      fs6.get("gate_passed") is True)

# ==================== 3. DISCOVERY REGISTER ====================
header("3. DISCOVERY REGISTER (discovery_register.py)")

register = DiscoveryRegister("/tmp")
record = register.register_discovery(
    mission_id="M001", source_gear="scraping", source_agent_id="agent-1",
    source_manager_id="mgr-1", discovery_types=["API_DISCOVERY"],
    materiality="high", evidence_references=["ev-1"],
    title="Test Discovery", description="Test"
)

check("register_discovery returns DiscoveryRecord",
      isinstance(record, DiscoveryRecord))

# Test persistence after discovery coordinator run
coord_register = coordinator._register
discovery_count = len(coord_register._discoveries)
check("coordinator register has discoveries",
      discovery_count > 0,
      f"count: {discovery_count}")

check("register.has_all_acknowledgments works",
      isinstance(coord_register.has_all_acknowledgments(list(coord_register._discoveries.keys())[0]), bool))

check("register.get_missing_acknowledgments returns list",
      isinstance(coord_register.get_missing_acknowledgments(list(coord_register._discoveries.keys())[0]), list))

check("register.get_approved_perspectives returns list",
      isinstance(coord_register.get_approved_perspectives(list(coord_register._discoveries.keys())[0]), list))

check("register.query_by_status works",
      isinstance(coord_register.query_by_status("DECIDED"), list))

check("register.query_by_gear works",
      isinstance(coord_register.query_by_gear("scraping"), list))

check("register.query_by_mission works",
      isinstance(coord_register.query_by_mission("M001"), list))

# Test register REQUIRED_GEARS
check("register REQUIRED_GEARS = 4 gears as set",
      coord_register.REQUIRED_GEARS == {"scraping", "mining", "security", "evidence"})


# ==================== 4. EVENT BUS ====================
header("4. EVENT BUS (event_bus.py)")

bus = DiscoveryEventBus()

# Test event types
check("DiscoveryEventType has DISCOVERY_DETECTED",
      hasattr(DiscoveryEventType, "DISCOVERY_DETECTED"))
check("DiscoveryEventType has DISCOVERY_REGISTERED",
      hasattr(DiscoveryEventType, "DISCOVERY_REGISTERED"))
check("DiscoveryEventType has DISCOVERY_BROADCAST",
      hasattr(DiscoveryEventType, "DISCOVERY_BROADCAST"))
check("DiscoveryEventType has DISCOVERY_ACKNOWLEDGED",
      hasattr(DiscoveryEventType, "DISCOVERY_ACKNOWLEDGED"))
check("DiscoveryEventType has gate and synthesis events",
      hasattr(DiscoveryEventType, "DISCOVERY_PERSPECTIVE_GATE_PASSED") and
      hasattr(DiscoveryEventType, "DISCOVERY_SYNTHESIS_COMPLETED"))

# Test publish
event = DiscoveryEvent.create(
    event_type=DiscoveryEventType.DISCOVERY_DETECTED,
    discovery_id="D001", mission_id="M001", correlation_id="C001",
    causation_id="CAU001", producer="scraping", receiver="ALL",
    gear="scraping", manager="mgr-1", evidence_reference="ev-1"
)
bus.publish(event)
check("publish adds event (count=1)",
      bus.event_count == 1,
      f"count={bus.event_count}")

# Test subscribe
received_events = []
def handler(ev):
    received_events.append(ev)

bus.subscribe(DiscoveryEventType.DISCOVERY_DETECTED, handler)

event2 = DiscoveryEvent.create(
    event_type=DiscoveryEventType.DISCOVERY_DETECTED,
    discovery_id="D002", mission_id="M001", correlation_id="C002",
    causation_id="CAU002", producer="scraping", receiver="ALL",
    gear="scraping", manager="mgr-1", evidence_reference="ev-2"
)
bus.publish(event2)
check("subscriber receives event (count=2, received=1)",
      len(received_events) == 1,
      f"received={len(received_events)}")

# Test multiple subscribers
received2 = []
def handler2(ev):
    received2.append(ev)

bus.subscribe(DiscoveryEventType.DISCOVERY_DETECTED, handler2)

event3 = DiscoveryEvent.create(
    event_type=DiscoveryEventType.DISCOVERY_DETECTED,
    discovery_id="D003", mission_id="M001", correlation_id="C003",
    causation_id="CAU003", producer="scraping", receiver="ALL",
    gear="scraping", manager="mgr-1", evidence_reference="ev-3"
)
bus.publish(event3)
check("multiple subscribers receive same event (handler1: +1, handler2: +1)",
      len(received_events) == 2 and len(received2) == 1)

# Test get_events_for_discovery
events = bus.get_events_for_discovery("D001")
check("get_events_for_discovery returns correct events",
      len(events) == 1 and events[0].discovery_id == "D001")

# Test get_events_by_type
typed_events = bus.get_events_by_type(DiscoveryEventType.DISCOVERY_DETECTED)
check("get_events_by_type filters correctly",
      len(typed_events) == 3)

# Test to_dict_list
dict_list = bus.to_dict_list()
check("to_dict_list returns list of dicts",
      len(dict_list) == 3 and isinstance(dict_list[0], dict))

# Test clear
bus.clear()
check("clear() resets event count",
      bus.event_count == 0)

# Test get_timeline
bus.publish(event)
bus.publish(event2)
timeline = bus.get_timeline()
check("get_timeline returns sorted events",
      len(timeline) == 2)

# Test DiscoveryEvent.to_dict()
check("DiscoveryEvent.to_dict() has required fields",
      all(k in event.to_dict() for k in ["event_id", "event_type", "discovery_id", "mission_id",
                                          "correlation_id", "causation_id", "producer", "receiver"]))

# ==================== 5. PERSPECTIVE GATE ====================
header("5. PERSPECTIVE GATE (perspective_gate.py)")

gate_bus = DiscoveryEventBus()
gate = DiscoveryPerspectiveGate(gate_bus)

check("perspective gate REQUIRED_GEARS = {'SCRAPING','MINING','SECURITY','EVIDENCE'}",
      gate.REQUIRED_GEARS == {"SCRAPING", "MINING", "SECURITY", "EVIDENCE"})

# Create 4 approved perspectives
perspectives = []
for gear_name in ["scraping", "mining", "security", "evidence"]:
    p = DiscoveryPerspective.create(
        discovery_id="D001", mission_id="M001", correlation_id="C001",
        gear=gear_name, producing_agent_id=f"agent-{gear_name}",
        approving_manager_id=f"mgr-{gear_name}",
        interpretation=f"Test interpretation from {gear_name}",
        evidence_ids=["ev-1"],
        opportunities=[], risks=[], uncertainties=[], contradictions=[],
        recommended_actions=[],
        operational_impact="", data_acquisition_impact="",
        mining_impact="", security_impact="",
        scope_impact="", authorization_impact="authorization assessed",
        confidence=0.75
    )
    p.status = PerspectiveStatus.MANAGER_APPROVED.value
    perspectives.append(p)

# Test gate passes with all 4
result_pass = gate.evaluate(
    "D001", "M001", "C001", "CAU001", perspectives,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
)
check("gate passes with all 4 approved perspectives",
      result_pass.passed is True)
check("gate_result has gate_name = DISCOVERY_PERSPECTIVE_COMPLETION",
      result_pass.gate_name == "DISCOVERY_PERSPECTIVE_COMPLETION")

# Test gate fails with only 3 perspectives
result_fail = gate.evaluate(
    "D002", "M001", "C002", "CAU002",
    perspectives[:3],  # missing 1
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
)
check("gate fails with only 3 perspectives",
      result_fail.passed is False)
check("gate failure includes missing gear",
      len(result_fail.failures) > 0)

# Test gate with unapproved perspective
p_not_approved = DiscoveryPerspective.create(
    discovery_id="D003", mission_id="M001", correlation_id="C003",
    gear="scraping", producing_agent_id="agent-scraping",
    approving_manager_id="mgr-scraping",
    interpretation="test", evidence_ids=["ev-1"],
    opportunities=[], risks=[], uncertainties=[], contradictions=[],
    recommended_actions=[],
    operational_impact="", data_acquisition_impact="",
    mining_impact="", security_impact="",
    scope_impact="", authorization_impact="authorization assessed",
    confidence=0.75
)
p_not_approved.status = PerspectiveStatus.CREATED.value
not_approved_list = [p_not_approved] + perspectives[1:]

result_not_approved = gate.evaluate(
    "D003", "M001", "C003", "CAU003",
    not_approved_list,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
)
check("gate fails when scraping not manager-approved",
      result_not_approved.passed is False)

# Test evidence_required=False default (should not block)
persp_no_evidence = DiscoveryPerspective.create(
    discovery_id="D004", mission_id="M001", correlation_id="C004",
    gear="scraping", producing_agent_id="agent-scraping",
    approving_manager_id="mgr-scraping",
    interpretation="test", evidence_ids=[],  # No evidence
    opportunities=[], risks=[], uncertainties=[], contradictions=[],
    recommended_actions=[],
    operational_impact="", data_acquisition_impact="",
    mining_impact="", security_impact="",
    scope_impact="", authorization_impact="auth",
    confidence=0.75
)
persp_no_evidence.status = PerspectiveStatus.MANAGER_APPROVED.value
no_ev_list = [persp_no_evidence] + perspectives[1:]

result_no_evidence = gate.evaluate(
    "D004", "M001", "C004", "CAU004",
    no_ev_list,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"}
)
check("gate passes with evidence_required=False (default)",
      result_no_evidence.passed is True)

# Test evidence_required=True
result_with_ev = gate.evaluate(
    "D004", "M001", "C004", "CAU004",
    no_ev_list,
    acknowledgments_gears={"SCRAPING", "MINING", "SECURITY", "EVIDENCE"},
    evidence_required=True,
)
check("gate fails with evidence_required=True on missing evidence",
      result_with_ev.passed is False)

# Test gate events emitted
check("gate emits gate event",
      gate_bus.event_count > 0,
      f"event_count={gate_bus.event_count}")

# ==================== 6. CROSS SHARING ====================
header("6. CROSS SHARING (cross_sharing.py)")

sharing_bus = DiscoveryEventBus()
sharing = CrossSharingEngine(sharing_bus)

check("CrossSharingEngine.ALL_GEARS = {scraping, mining, security, evidence}",
      sharing.ALL_GEARS == {"scraping", "mining", "security", "evidence"})

check("GEAR_PUBLISHED_EVENTS has all 4 gears",
      set(sharing.GEAR_PUBLISHED_EVENTS.keys()) == {"scraping", "mining", "security", "evidence"})

# Create approved perspective
scraping_persp = DiscoveryPerspective.create(
    discovery_id="D001", mission_id="M001", correlation_id="C001",
    gear="scraping", producing_agent_id="agent-scraping",
    approving_manager_id="mgr-scraping",
    interpretation="Test scraping interpretation",
    evidence_ids=["ev-1"],
    opportunities=["API access"], risks=["Rate limits"],
    uncertainties=[], contradictions=[],
    recommended_actions=["Map schema"],
    operational_impact="", data_acquisition_impact="",
    mining_impact="", security_impact="",
    scope_impact="", authorization_impact="",
    confidence=0.75
)
scraping_persp.status = PerspectiveStatus.MANAGER_APPROVED.value

# Test publish_approved_perspective
sharing.publish_approved_perspective(scraping_persp, "M001", "C001", "CAU001")
check("publish_approved_perspective emits events to other gears",
      sharing_bus.event_count > 0,
      f"event_count={sharing_bus.event_count}")

# Should emit 3 gear-specific events + 1 general = 4 per perspective
check("publish emits SCRAPING_PERSPECTIVE_PUBLISHED events",
      len(sharing_bus.get_events_by_type(DiscoveryEventType.SCRAPING_PERSPECTIVE_PUBLISHED)) == 3)
check("publish emits PERSPECTIVE_PUBLISHED general event",
      len(sharing_bus.get_events_by_type(DiscoveryEventType.PERSPECTIVE_PUBLISHED)) == 1)

# Test publish_approved_perspective rejects unapproved
unapproved_persp = DiscoveryPerspective.create(
    discovery_id="D002", mission_id="M001", correlation_id="C002",
    gear="scraping", producing_agent_id="agent-scraping",
    approving_manager_id="mgr-scraping",
    interpretation="test", evidence_ids=[],
    opportunities=[], risks=[], uncertainties=[], contradictions=[],
    recommended_actions=[],
    operational_impact="", data_acquisition_impact="",
    mining_impact="", security_impact="",
    scope_impact="", authorization_impact="",
    confidence=0.75
)
unapproved_persp.status = PerspectiveStatus.CREATED.value

try:
    sharing.publish_approved_perspective(unapproved_persp, "M001", "C002", "CAU002")
    check("publish_approved_perspective raises on unapproved perspective",
          False, "no exception raised")
except ValueError:
    check("publish_approved_perspective raises on unapproved perspective", True)

# Test observation
obs = sharing.add_observation(scraping_persp.perspective_id, "mining",
                                "Mining gear notes structured data opportunity", "agent-mining")
check("add_observation returns dict with observation",
      obs.get("type") == "OBSERVATION" and obs.get("observing_gear") == "mining")
check("get_observations returns list",
      len(sharing.get_observations(scraping_persp.perspective_id)) == 1)

# Test challenge
chal = sharing.add_challenge(scraping_persp.perspective_id, "security",
                               "Rate limit assumption needs verification", "agent-security")
check("add_challenge returns dict with challenge",
      chal.get("type") == "CHALLENGE")
check("get_challenges returns list",
      len(sharing.get_challenges(scraping_persp.perspective_id)) == 1)

# Test clarification request
req = sharing.request_clarification(scraping_persp.perspective_id, "evidence",
                                       "Please clarify evidence basis for confidence", "agent-evidence")
check("request_clarification returns dict",
      req.get("type") == "CLARIFICATION_REQUEST")

# Test update_perspective
updated = sharing.update_perspective(scraping_persp,
                                       "Updated: mining gear notes...", "agent-scraping")
check("update_perspective increases version",
      updated.version == scraping_persp.version + 1,
      f"version: {updated.version}")
check("update_perspective references previous version",
      updated.previous_version_id == scraping_persp.perspective_id)

# Test open_contradiction
contradiction = sharing.open_contradiction(scraping_persp.perspective_id, "evidence",
                                             "Evidence confidence contradicts mining", "agent-evidence")
check("open_contradiction returns dict",
      contradiction.get("type") == "CONTRADICTION")
check("has_contradictions returns True",
      sharing.has_contradictions(scraping_persp.perspective_id) is True)

# Test get_exchanges
exchanges = sharing.get_exchanges()
check("get_exchanges returns all exchanges",
      len(exchanges) > 0)


# ==================== 7. EVIDENCE SYNTHESIS ====================
header("7. EVIDENCE SYNTHESIS (evidence_synthesis.py)")

synth_bus = DiscoveryEventBus()
synth_engine = EvidenceSynthesisEngine(synth_bus)

# Create approved perspectives for synthesis
synth_persps = []
for gear_name in ["scraping", "mining", "security", "evidence"]:
    p = DiscoveryPerspective.create(
        discovery_id="D001", mission_id="M001", correlation_id="C001",
        gear=gear_name, producing_agent_id=f"agent-{gear_name}",
        approving_manager_id=f"mgr-{gear_name}",
        interpretation=f"Structured catalog discovery analysis from {gear_name}. "
                       f"This API provides structured product data.",
        evidence_ids=["ev-1", "ev-2"],
        opportunities=[f"Opportunity from {gear_name}"],
        risks=[f"Risk from {gear_name}"],
        uncertainties=[f"Uncertainty from {gear_name}"],
        contradictions=[],
        recommended_actions=[f"Action from {gear_name}"],
        operational_impact="", data_acquisition_impact="",
        mining_impact="", security_impact="not a vulnerability",
        scope_impact="within scope",
        authorization_impact="authorization required",
        confidence=0.75
    )
    p.status = PerspectiveStatus.MANAGER_APPROVED.value
    synth_persps.append(p)

# Test synthesis
synthesis = synth_engine.synthesize(
    "D001", "M001", "C001", "CAU001",
    synth_persps,
    contradictions=[],
    evidence_manager_id="EVIDENCE_INTEGRATION_MANAGER",
)

check("synthesize returns SynthesisResult",
      isinstance(synthesis, SynthesisResult))

check("synthesis has scraping_established",
      len(synthesis.scraping_established) > 0)

check("synthesis has mining_established",
      len(synthesis.mining_established) > 0)

check("synthesis has security_established",
      len(synthesis.security_established) > 0)

check("synthesis has evidence_established",
      len(synthesis.evidence_established) > 0)

check("synthesis has areas_of_agreement",
      len(synthesis.areas_of_agreement) > 0)

check("synthesis has areas_of_contradiction",
      isinstance(synthesis.areas_of_contradiction, list))

check("synthesis has unresolved_uncertainty",
      len(synthesis.unresolved_uncertainty) > 0)

check("synthesis has scope_implications",
      len(synthesis.scope_implications) > 0)

check("synthesis has authorization_implications",
      len(synthesis.authorization_implications) > 0)

check("synthesis has safe_options",
      len(synthesis.safe_options) > 0)

check("synthesis has blocked_options",
      len(synthesis.blocked_options) > 0)

check("synthesis has recommended_next_phase_options",
      len(synthesis.recommended_next_phase_options) > 0)

check("synthesis has produced_by = EVIDENCE_INTEGRATION_MANAGER",
      synthesis.produced_by == "EVIDENCE_INTEGRATION_MANAGER")

# Test synthesis events
check("synthesis emits STARTED and COMPLETED events",
      len(synth_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_SYNTHESIS_STARTED)) == 1 and
      len(synth_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_SYNTHESIS_COMPLETED)) == 1)

# Test get_synthesis
retrieved = synth_engine.get_synthesis("D001")
check("get_synthesis returns the synthesis",
      retrieved is synthesis)

# Test synthesis with contradictions
synthesis_with_contra = synth_engine.synthesize(
    "D002", "M001", "C002", "CAU002",
    synth_persps,
    contradictions=[{"severity": "high", "description": "Test contradiction"}],
    evidence_manager_id="EVIDENCE_INTEGRATION_MANAGER",
)
check("synthesis preserves registered contradictions",
      len(synthesis_with_contra.areas_of_contradiction) > 0)

# ==================== 8. DISCOVERY BROADCAST ====================
header("8. DISCOVERY BROADCAST (discovery_broadcast.py)")

broadcast_bus = DiscoveryEventBus()
broadcast = DiscoveryBroadcast(broadcast_bus)

check("broadcast REQUIRED_GEARS = ['scraping','mining','security','evidence']",
      broadcast.REQUIRED_GEARS == ["scraping", "mining", "security", "evidence"])

# Create test discovery
test_disc = DiscoveryRecord.create(
    mission_id="M001", source_gear="scraping", source_agent_id="agent-1",
    source_manager_id="mgr-1", discovery_types=["API_DISCOVERY"],
    materiality="high", evidence_references=["ev-1"],
    title="Broadcast Test", description="Test broadcast"
)

# Test broadcast_discovery
ack_callback_calls = []
def ack_callback(gear, agent_id):
    ack_callback_calls.append((gear, agent_id))

broadcast.broadcast_discovery(test_disc, callback=ack_callback)

# Should emit: 1 DISCOVERY_DETECTED + 1 DISCOVERY_REGISTERED + 4 DISCOVERY_BROADCAST = 6 events
check("broadcast_discovery emits DETECTED event",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_DETECTED)) == 1)
check("broadcast_discovery emits REGISTERED event",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_REGISTERED)) == 1)
check("broadcast_discovery emits 4 BROADCAST events (one per gear)",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_BROADCAST)) == 4)

# Test acknowledge_receipt
ack_event = broadcast.acknowledge_receipt(
    test_disc.discovery_id, test_disc.mission_id,
    test_disc.correlation_id, test_disc.causation_id,
    "scraping", "agent-scraping"
)
check("acknowledge_receipt returns DiscoveryEvent",
      isinstance(ack_event, DiscoveryEvent))
check("acknowledge_receipt triggers callback",
      len(ack_callback_calls) == 1)
check("acknowledge_receipt emits RECEIVED",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_RECEIVED)) == 1)
check("acknowledge_receipt emits ACKNOWLEDGED",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_ACKNOWLEDGED)) == 1)

# Acknowledge remaining gears
for gear in ["mining", "security", "evidence"]:
    broadcast.acknowledge_receipt(
        test_disc.discovery_id, test_disc.mission_id,
        test_disc.correlation_id, test_disc.causation_id,
        gear, f"agent-{gear}"
    )

# Test check_acknowledgments
ack_status = broadcast.check_acknowledgments(test_disc.discovery_id)
check("check_acknowledgments: all_acknowledged=True",
      ack_status["all_acknowledged"] is True)
check("check_acknowledgments: 4 acknowledged",
      len(ack_status["acknowledged"]) == 4)
check("check_acknowledgments: 0 missing",
      len(ack_status["missing"]) == 0)

# Test timeout
timeout_status = broadcast.check_for_timeouts(test_disc.discovery_id)
check("check_for_timeouts: no timeouts (all acknowledged)",
      len(timeout_status["timed_out"]) == 0)

# Test retry_gear
retry_event = broadcast.retry_gear(test_disc, "scraping")
check("retry_gear emits DISCOVERY_RETRY",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_RETRY)) == 1)
check("retry_gear emits new DISCOVERY_BROADCAST",
      len(broadcast_bus.get_events_by_type(DiscoveryEventType.DISCOVERY_BROADCAST)) == 5)

# Test timeouts
broadcast.set_timeout_seconds(60)
check("set_timeout_seconds/get_timeout_seconds",
      broadcast.get_timeout_seconds() == 60)

# ==================== FINAL REPORT ====================
header("RESULTS SUMMARY")
print(f"\n  PASSED: {PASS}/{TOTAL}")
print(f"  FAILED: {FAIL}/{TOTAL}")

if FAIL == 0:
    print("\n  ✓ ALL CHECKS PASSED")
else:
    print(f"\n  ✗ {FAIL} CHECKS FAILED")

# Return exit code for CI
if __name__ == "__main__":
    sys.exit(0 if FAIL == 0 else 1)
