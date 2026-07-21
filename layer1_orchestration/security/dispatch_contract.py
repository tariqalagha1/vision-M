"""
ATLAS PHASE 1 — Shared Engine Dispatch Contract
================================================
Engine-agnostic dispatch interface for Scraping, Mining, and Security engines.
All dispatch flows through this shared contract — no engine-specific bypasses.

MYC-CHAIN-INV-001 enforced: no execution outside this contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


# ═══════════════════════════════════════════════════════════════
# Engine identity
# ═══════════════════════════════════════════════════════════════

class TargetEngine(str, Enum):
    """Canonical engine identifiers used in routing and dispatch."""
    SCRAPING = "scraping"
    MINING = "mining"
    SECURITY = "security"


# ═══════════════════════════════════════════════════════════════
# Dispatch status
# ═══════════════════════════════════════════════════════════════

class DispatchStatus(str, Enum):
    """Result of a dispatch operation."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    ENGINE_UNAVAILABLE = "ENGINE_UNAVAILABLE"
    INVALID_PARAMETERS = "INVALID_PARAMETERS"
    UNAUTHORIZED = "UNAUTHORIZED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    DEPTH_EXHAUSTED = "DEPTH_EXHAUSTED"
    LOOP_DETECTED = "LOOP_DETECTED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"


# ═══════════════════════════════════════════════════════════════
# Termination reasons (machine-readable)
# ═══════════════════════════════════════════════════════════════

class TerminationReason(str, Enum):
    """Machine-readable termination reasons for controlled stop."""
    DEPTH_CAP_REACHED = "DEPTH_CAP_REACHED"
    HYPOTHESIS_BUDGET_EXHAUSTED = "HYPOTHESIS_BUDGET_EXHAUSTED"
    CHAIN_BUDGET_EXHAUSTED = "CHAIN_BUDGET_EXHAUSTED"
    LOOP_GUARD_DUPLICATE_WORK = "LOOP_GUARD_DUPLICATE_WORK"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    TENANT_CONTEXT_INVALID = "TENANT_CONTEXT_INVALID"
    ENGINE_ADAPTER_FAILURE = "ENGINE_ADAPTER_FAILURE"
    MANUAL_KILL_SWITCH = "MANUAL_KILL_SWITCH"
    NORMAL_COMPLETION = "NORMAL_COMPLETION"


# ═══════════════════════════════════════════════════════════════
# Shared dispatch request
# ═══════════════════════════════════════════════════════════════

@dataclass
class DispatchRequest:
    """Structured dispatch request — engine-agnostic, symmetric across all engines."""

    # ── Identification ──
    dispatch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    hypothesis_id: str = ""
    source_finding_id: str = ""
    source_event_id: str = ""

    # ── Engine routing ──
    source_engine: str = ""
    target_engine: str = ""

    # ── Target ──
    target_asset: str = ""
    normalized_asset: str = ""
    action_type: str = ""
    action_parameters: Dict[str, Any] = field(default_factory=dict)

    # ── Context ──
    tenant_id: str = ""
    authorization_context: Dict[str, Any] = field(default_factory=dict)
    scope_context: Dict[str, Any] = field(default_factory=dict)

    # ── Budgets ──
    cascade_depth: int = 0
    hypothesis_request_budget: int = 10
    chain_request_budget_remaining: int = 100

    # ── Timestamps ──
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def create(cls, **kwargs) -> DispatchRequest:
        return cls(**kwargs)

    def to_dict(self) -> dict:
        return {
            "dispatch_id": self.dispatch_id,
            "chain_id": self.chain_id,
            "hypothesis_id": self.hypothesis_id,
            "source_finding_id": self.source_finding_id,
            "source_event_id": self.source_event_id,
            "source_engine": self.source_engine,
            "target_engine": self.target_engine,
            "target_asset": self.target_asset,
            "normalized_asset": self.normalized_asset,
            "action_type": self.action_type,
            "action_parameters": self.action_parameters,
            "tenant_id": self.tenant_id,
            "authorization_context": self.authorization_context,
            "scope_context": self.scope_context,
            "cascade_depth": self.cascade_depth,
            "hypothesis_request_budget": self.hypothesis_request_budget,
            "chain_request_budget_remaining": self.chain_request_budget_remaining,
            "created_at": self.created_at,
        }


# ═══════════════════════════════════════════════════════════════
# Shared dispatch result
# ═══════════════════════════════════════════════════════════════

@dataclass
class DispatchResult:
    """Structured dispatch result — symmetric across all engines."""

    # ── Identification ──
    dispatch_id: str = ""
    chain_id: str = ""
    hypothesis_id: str = ""

    # ── Engine routing ──
    source_engine: str = ""
    target_engine: str = ""

    # ── Target ──
    target_asset: str = ""
    normalized_asset: str = ""
    action_type: str = ""

    # ── Execution ──
    execution_status: str = DispatchStatus.SUCCESS.value
    request_count: int = 0
    started_at: str = ""
    completed_at: str = ""

    # ── Result ──
    result_payload: Dict[str, Any] = field(default_factory=dict)
    result_summary: str = ""

    # ── Errors ──
    error_code: str = ""
    error_message: str = ""

    # ── Termination ──
    termination_reason: str = ""

    @classmethod
    def create(cls, **kwargs) -> DispatchResult:
        return cls(**kwargs)

    @property
    def is_success(self) -> bool:
        return self.execution_status == DispatchStatus.SUCCESS.value

    def to_dict(self) -> dict:
        return {
            "dispatch_id": self.dispatch_id,
            "chain_id": self.chain_id,
            "hypothesis_id": self.hypothesis_id,
            "source_engine": self.source_engine,
            "target_engine": self.target_engine,
            "target_asset": self.target_asset,
            "normalized_asset": self.normalized_asset,
            "action_type": self.action_type,
            "execution_status": self.execution_status,
            "request_count": self.request_count,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result_payload": self.result_payload,
            "result_summary": self.result_summary,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "termination_reason": self.termination_reason,
        }


# ═══════════════════════════════════════════════════════════════
# Asset normalization
# ═══════════════════════════════════════════════════════════════

def normalize_asset(asset: str) -> str:
    """Normalize an asset reference for stable loop-prevention identity.

    Rules applied:
    - Strip scheme (https:// → empty)
    - Lowercase
    - Remove trailing slash
    - Remove default port :443 for https, :80 for http
    """
    if not asset:
        return asset

    normalized = asset.strip().lower()

    # Strip scheme
    for scheme in ("https://", "http://"):
        if normalized.startswith(scheme):
            normalized = normalized[len(scheme):]
            break

    # Remove trailing slash
    normalized = normalized.rstrip("/")

    # Remove default ports
    if normalized.endswith(":443"):
        normalized = normalized[:-4]
    elif normalized.endswith(":80"):
        normalized = normalized[:-3]

    return normalized


# ═══════════════════════════════════════════════════════════════
# Work identity for loop prevention
# ═══════════════════════════════════════════════════════════════

def make_work_identity(
    target_engine: str,
    normalized_asset: str,
    action_type: str,
) -> str:
    """Create a stable work-identity tuple key for loop prevention.

    Returns a pipe-delimited string suitable for use in a set.
    """
    return f"{target_engine}|{normalized_asset}|{action_type}"
