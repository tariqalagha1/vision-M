#!/usr/bin/env python3
"""
Test script for Vision-M Webhook Receiver.

Tests:
  1. GET /health — verify 200 + handlers registered
  2. POST /webhook with valid HMAC — verify 200 + scan_request enqueued
  3. POST /webhook with invalid HMAC — verify 403
  4. POST /webhook with schedule_update — verify 200
  5. POST /webhook with status_check — verify 200
  6. GET /webhook/status — verify handler list + recent/failed events

Uses FastAPI TestClient — no network server needed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys

os.environ["WEBHOOK_SECRET"] = "test-secret-key-12345"
os.environ["WEBHOOK_PORT"] = "8644"

sys.path.insert(0, "/data/workspace/vision-M")

from fastapi.testclient import TestClient
from layer1_orchestration.webhook.receiver import create_app, validate_hmac


def make_hmac_signature(body: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature header value."""
    digest = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def main() -> int:
    secret = os.environ["WEBHOOK_SECRET"]

    print("=" * 60)
    print("Vision-M Webhook Receiver — Test Suite")
    print("=" * 60)
    failures = 0
    tests = 0

    # ── Create app and client ────────────────────────────────────
    print("\n[INIT] Creating FastAPI app...")
    app = create_app(secret=secret)
    print("[INIT] App created successfully")
    client = TestClient(app)

    try:
        # ── Test 1: GET /health ──────────────────────────────────
        tests += 1
        print(f"\n[TEST {tests}] GET /health")
        resp = client.get("/health")
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["status"] == "ok", f"Expected 'ok', got {data['status']}"
        assert "timestamp" in data, "Missing timestamp"
        assert "handlers" in data, "Missing handlers"
        assert sorted(data["handlers"]) == sorted(
            ["scan_request", "schedule_update", "status_check"]
        ), f"Unexpected handlers: {data['handlers']}"
        print(f"  => PASS")

        # ── Test 2: POST /webhook with valid HMAC (scan_request) ─
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook with valid HMAC (scan_request)")
        payload = {
            "event_type": "scan_request",
            "event_id": "evt-scan-001",
            "target": "example.com",
            "tenant_id": "test-tenant",
            "mission_id": "m-001",
        }
        body = json.dumps(payload).encode("utf-8")
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": sig,
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["status"] == "received", f"Expected 'received', got {data['status']}"
        assert data["event_id"] == "evt-scan-001"
        assert data["event_type"] == "scan_request"
        assert data["handler_result"]["action"] == "scan_enqueued"
        assert data["handler_result"]["target"] == "example.com"
        print(f"  => PASS")

        # ── Test 3: POST /webhook with invalid HMAC ──────────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook with invalid HMAC")
        payload = {
            "event_type": "scan_request",
            "event_id": "evt-bad-hmac",
            "target": "evil.com",
        }
        body = json.dumps(payload).encode("utf-8")
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": "sha256=bad00000digest0000000000000000000000000000",
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"
        assert data["detail"]["status"] == "error"
        assert "HMAC" in data["detail"]["message"]
        print(f"  => PASS")

        # ── Test 4: POST /webhook with schedule_update ───────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook with schedule_update")
        payload = {
            "event_type": "schedule_update",
            "event_id": "evt-sched-001",
            "schedule_id": "sched-daily-001",
        }
        body = json.dumps(payload).encode("utf-8")
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": sig,
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 200
        assert data["status"] == "received"
        assert data["handler_result"]["action"] == "schedule_acknowledged"
        print(f"  => PASS")

        # ── Test 5: POST /webhook with status_check ──────────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook with status_check")
        payload = {
            "event_type": "status_check",
            "event_id": "evt-status-001",
            "component": "worker-pool-1",
        }
        body = json.dumps(payload).encode("utf-8")
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": sig,
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 200
        assert data["status"] == "received"
        assert data["handler_result"]["action"] == "status_checked"
        print(f"  => PASS")

        # ── Test 6: POST /webhook without event_type ─────────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook without event_type field")
        payload = {"foo": "bar", "event_id": "no-type"}
        body = json.dumps(payload).encode("utf-8")
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": sig,
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
        assert data["detail"]["status"] == "error"
        assert "event_type" in data["detail"]["message"]
        print(f"  => PASS")

        # ── Test 7: POST /webhook with unknown event_type ────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook with unknown event_type")
        payload = {
            "event_type": "unknown_event",
            "event_id": "evt-unknown-001",
        }
        body = json.dumps(payload).encode("utf-8")
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature-256": sig,
            },
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Body: {json.dumps(data, indent=2)}")
        assert resp.status_code == 200, f"Expected 200 (acknowledged), got {resp.status_code}"
        assert data["status"] == "received"
        assert data["handler"] is None
        assert "no handler" in data["note"].lower()
        print(f"  => PASS")

        # ── Test 8: GET /webhook/status — full report ────────────
        tests += 1
        print(f"\n[TEST {tests}] GET /webhook/status — full report")
        resp = client.get("/webhook/status")
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Handlers: {data.get('handlers')}")
        print(f"  Recent events: {len(data.get('recent_events', []))}")
        print(f"  Failed events: {len(data.get('failed_events', []))}")
        assert resp.status_code == 200
        assert sorted(data["handlers"]) == sorted(
            ["scan_request", "schedule_update", "status_check"]
        )
        # Recent: scan_request(valid), schedule_update, status_check, unknown_event = 4 accepted
        assert len(data["recent_events"]) >= 4, f"Expected >=4 recent events, got {len(data['recent_events'])}"
        # Failed: invalid HMAC, missing event_type = 2 failures
        assert len(data["failed_events"]) >= 2, f"Expected >=2 failed events, got {len(data['failed_events'])}"
        print(f"  => PASS")

        # ── Test 9: No HMAC when secret is set ───────────────────
        tests += 1
        print(f"\n[TEST {tests}] POST /webhook without X-Signature-256 header")
        payload = {
            "event_type": "status_check",
            "event_id": "evt-no-sig",
        }
        body = json.dumps(payload).encode("utf-8")
        resp = client.post(
            "/webhook",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        assert resp.status_code == 403, f"Expected 403 (no signature), got {resp.status_code}"
        print(f"  => PASS")

        # ── Test 9b: HMAC validation unit test ───────────────────
        tests += 1
        print(f"\n[TEST {tests}] HMAC validation unit test")
        body = b"test body"
        sig = make_hmac_signature(body, secret)
        assert validate_hmac(body, sig, secret) is True, "Valid HMAC should pass"
        assert validate_hmac(body, "sha256=bad", secret) is False, "Bad HMAC should fail"
        assert validate_hmac(body, None, secret) is False, "None header should fail"
        assert validate_hmac(body, "", secret) is False, "Empty header should fail"
        assert validate_hmac(body, sig, "") is True, "Empty secret should skip validation"
        print(f"  => PASS")

    except AssertionError as exc:
        print(f"\n  => FAIL: {exc}")
        failures += 1
    except Exception as exc:
        print(f"\n  => FAIL: {type(exc).__name__}: {exc}")
        failures += 1

    # ── Result ───────────────────────────────────────────────────
    print("\n" + "=" * 60)
    if failures == 0:
        print(f"PASS — All {tests} tests passed")
    else:
        print(f"FAIL — {failures}/{tests} tests failed")
    print("=" * 60)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
