#!/usr/bin/env python3
"""
Test script for Vision-M Webhook Hardening (H3, H6).

Tests:
  H3 — Persist failed events to JSON:
    1. Force failed events (bad HMAC, missing event_type)
    2. Verify _failed_events.json exists and has entries
    3. Call POST /webhook/failed/retry and confirm file is cleared

  H6 — Rate limiting:
    4. Temporarily lower rate limit, send max+1 requests
    5. Verify 101st (or trigger) gets 429 with "Rate limit exceeded"
    6. Verify after window, requests succeed again
"""

from __future__ import annotations

import json
import os
import sys
import time

os.environ["WEBHOOK_SECRET"] = "test-secret-key-harden"
os.environ["WEBHOOK_PORT"] = "8645"

sys.path.insert(0, "/data/workspace/vision-M")

import hashlib
import hmac

from fastapi.testclient import TestClient
from layer1_orchestration.webhook.receiver import (
    create_app,
    FAILED_EVENTS_PATH,
    _rate_limiter,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
)


def make_hmac_signature(body: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature header value."""
    digest = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def main() -> int:
    print("=" * 60)
    print("Vision-M Webhook Hardening — Test Suite (H3, H6)")
    print("=" * 60)
    failures = 0
    tests = 0

    # Clean up any leftover failed events file from previous runs
    if os.path.exists(FAILED_EVENTS_PATH):
        os.remove(FAILED_EVENTS_PATH)

    # ── Create app and client ────────────────────────────────────
    print("\n[INIT] Creating FastAPI app...")
    app = create_app(secret="test-secret-key-harden")
    client = TestClient(app)
    receiver = app.state.receiver
    print("[INIT] App created successfully")

    # ═══════════════════════════════════════════════════════════════
    # H3 — Persist failed events to JSON
    # ═══════════════════════════════════════════════════════════════

    try:
        # ── H3 Test 1: Force failed events ────────────────────────
        tests += 1
        print(f"\n[H3 TEST {tests}] Force failed events (bad HMAC + missing event_type)")
        # Event 1: Invalid HMAC
        client.post(
            "/webhook",
            content=json.dumps({"event_type": "scan_request"}).encode(),
            headers={"X-Signature-256": "sha256=bad00000digest0000000000000000000000000000"},
        )
        # Event 2: Missing event_type
        client.post(
            "/webhook",
            content=json.dumps({"foo": "bar"}).encode(),
            headers={"X-Signature-256": "sha256=irrelevant"},  # HMAC won't matter if secret set
        )

        # Check in-memory failed events
        failed = receiver.failed_events
        print(f"  In-memory failed events: {len(failed)}")
        assert len(failed) >= 2, f"Expected >=2 failed events, got {len(failed)}"
        print(f"  => PASS")

        # ── H3 Test 2: Verify _failed_events.json exists ──────────
        tests += 1
        print(f"\n[H3 TEST {tests}] Verify _failed_events.json exists and has entries")
        assert os.path.exists(FAILED_EVENTS_PATH), (
            f"FAILED_EVENTS_PATH ({FAILED_EVENTS_PATH}) does not exist"
        )
        with open(FAILED_EVENTS_PATH, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        print(f"  File lines: {len(lines)}")
        print(f"  File path: {FAILED_EVENTS_PATH}")
        assert len(lines) >= 2, f"Expected >=2 lines in file, got {len(lines)}"
        # Verify valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "timestamp" in parsed, f"Missing timestamp in entry: {parsed}"
            assert "reason" in parsed, f"Missing reason in entry: {parsed}"
        print(f"  => PASS")

        # ── H3 Test 3: Call retry endpoint and confirm file cleared ─
        tests += 1
        print(f"\n[H3 TEST {tests}] Call POST /webhook/failed/retry and confirm clearing")
        resp = client.post("/webhook/failed/retry")
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Count: {data.get('count')}")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["status"] == "retried"
        assert data["count"] >= 2, f"Expected count >=2, got {data['count']}"
        # Verify in-memory list cleared
        assert len(receiver.failed_events) == 0, (
            f"In-memory failed events not cleared: {len(receiver.failed_events)}"
        )
        # Verify file cleared (should be deleted or empty)
        file_exists_after = os.path.exists(FAILED_EVENTS_PATH)
        print(f"  File exists after retry: {file_exists_after}")
        print(f"  In-memory failed after retry: {len(receiver.failed_events)}")
        # The file should be removed by _clear_failed_events
        assert not file_exists_after, (
            f"_failed_events.json should be deleted after retry, but still exists"
        )
        print(f"  => PASS")

    except AssertionError as exc:
        print(f"\n  => FAIL: {exc}")
        failures += 1
    except Exception as exc:
        print(f"\n  => FAIL: {type(exc).__name__}: {exc}")
        import traceback; traceback.print_exc()
        failures += 1

    # ═══════════════════════════════════════════════════════════════
    # H6 — Rate limiting
    # ═══════════════════════════════════════════════════════════════

    try:
        # ── H6 setup: lower rate limits for test ──────────────────
        # Monkey-patch the rate limiter for practical testing
        import layer1_orchestration.webhook.receiver as receiver_mod
        original_max = receiver_mod.RATE_LIMIT_MAX
        original_window = receiver_mod.RATE_LIMIT_WINDOW
        receiver_mod.RATE_LIMIT_MAX = 5   # Only 5 requests per window for testing
        receiver_mod.RATE_LIMIT_WINDOW = 3  # 3-second window for fast testing
        # Clear existing rate limiter state
        receiver_mod._rate_limiter.clear()

        # ── H6 Test 4: Send RATE_LIMIT_MAX+1 requests, verify 429 ──
        tests += 1
        print(f"\n[H6 TEST {tests}] Send {receiver_mod.RATE_LIMIT_MAX + 1} rapid requests, verify rate limit")
        secret = os.environ["WEBHOOK_SECRET"]
        success_count = 0
        rate_limited = False
        for i in range(receiver_mod.RATE_LIMIT_MAX + 1):
            payload = json.dumps({
                "event_type": "status_check",
                "event_id": f"rl-test-{i}",
                "component": "test",
            })
            body = payload.encode()
            sig = make_hmac_signature(body, secret)
            resp = client.post(
                "/webhook",
                content=body,
                headers={"X-Signature-256": sig},
            )
            if resp.status_code == 200:
                success_count += 1
            elif resp.status_code == 429:
                rate_limited = True
                print(f"  Request {i}: got 429 (rate limited)")
                break
            else:
                print(f"  Request {i}: unexpected status {resp.status_code}: {resp.json()}")

        print(f"  Successful requests: {success_count}")
        print(f"  Was rate limited: {rate_limited}")
        assert rate_limited, (
            f"Expected to be rate limited after {receiver_mod.RATE_LIMIT_MAX} requests, "
            f"but never got 429 (success_count={success_count})"
        )
        # Verify the 429 response body
        resp = client.post(
            "/webhook",
            content=json.dumps({"event_type": "status_check", "event_id": "check-429", "component": "test"}).encode(),
            headers={"X-Signature-256": make_hmac_signature(
                json.dumps({"event_type": "status_check", "event_id": "check-429", "component": "test"}).encode(), secret
            )},
        )
        data = resp.json()
        assert resp.status_code == 429, f"Expected 429, got {resp.status_code}"
        assert data["status"] == "error"
        assert "Rate limit exceeded" in data["message"]
        print(f"  => PASS")

        # ── H6 Test 5: Verify requests succeed after window passes ─
        tests += 1
        print(f"\n[H6 TEST {tests}] Wait for rate limit window to pass, verify requests succeed again")
        print(f"  Waiting {receiver_mod.RATE_LIMIT_WINDOW + 1}s for window to expire...")
        time.sleep(receiver_mod.RATE_LIMIT_WINDOW + 1)  # Wait for window to pass
        # Send a fresh request with valid HMAC
        payload = json.dumps({
            "event_type": "status_check",
            "event_id": "post-window",
            "component": "test",
        })
        body = payload.encode()
        sig = make_hmac_signature(body, secret)
        resp = client.post(
            "/webhook",
            content=body,
            headers={"X-Signature-256": sig},
        )
        print(f"  Status after window: {resp.status_code}")
        assert resp.status_code == 200, (
            f"Expected 200 after window passes, got {resp.status_code}: {resp.json()}"
        )
        data = resp.json()
        assert data["status"] == "received"
        print(f"  => PASS")

        # ── Restore original rate limits ──────────────────────────
        receiver_mod.RATE_LIMIT_MAX = original_max
        receiver_mod.RATE_LIMIT_WINDOW = original_window
        receiver_mod._rate_limiter.clear()

    except AssertionError as exc:
        print(f"\n  => FAIL: {exc}")
        failures += 1
        # Restore original rate limits even on failure
        try:
            receiver_mod.RATE_LIMIT_MAX = original_max
            receiver_mod.RATE_LIMIT_WINDOW = original_window
            receiver_mod._rate_limiter.clear()
        except Exception:
            pass
    except Exception as exc:
        print(f"\n  => FAIL: {type(exc).__name__}: {exc}")
        import traceback; traceback.print_exc()
        failures += 1
        try:
            receiver_mod.RATE_LIMIT_MAX = original_max
            receiver_mod.RATE_LIMIT_WINDOW = original_window
            receiver_mod._rate_limiter.clear()
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════
    # Cleanup
    # ═══════════════════════════════════════════════════════════════
    if os.path.exists(FAILED_EVENTS_PATH):
        os.remove(FAILED_EVENTS_PATH)

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
