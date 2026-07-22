"""
Vision-M Webhook Receiver
=========================
FastAPI-based webhook receiver with HMAC signature validation,
event-type routing, JobQueue integration, health check, and retry tracking.

Port: WEBHOOK_PORT env (default 8643)
Secret: WEBHOOK_SECRET env

Endpoints:
  POST /webhook        — accept incoming webhooks (HMAC validated)
  GET  /health         — health check
  GET  /webhook/status — registered handlers + recent events
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

# ── JobQueue integration ──────────────────────────────────────────
from layer1_orchestration.execution.job_contract import JobContract, JobRecord
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_queue import JobQueue

# ═══════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════

DEFAULT_PORT = 8643
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", DEFAULT_PORT))
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
FAILED_EVENTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_failed_events.json")

# ── Rate limiting configuration ──────────────────────────────────
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 100     # requests per window


# ═══════════════════════════════════════════════════════════════════
# HMAC validation
# ═══════════════════════════════════════════════════════════════════

def validate_hmac(body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Validate HMAC-SHA256 signature.

    The signature header should be: sha256=<hex digest>
    """
    if not secret:
        # No secret configured — skip validation (development mode)
        return True
    if not signature_header:
        return False

    # Parse: "sha256=<hex>"
    if not signature_header.startswith("sha256="):
        return False

    expected_hex = signature_header[len("sha256="):]
    computed_digest = hmac.new(
        secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(computed_digest, expected_hex)


# ── Rate limiter ──────────────────────────────────────────────────
_rate_limiter: Dict[str, List[float]] = {}

def _check_rate_limit(client_ip: str) -> bool:
    """Check if client_ip has exceeded the rate limit.

    Returns True if the request is allowed, False if rate limited.
    """
    now = time.time()
    if client_ip not in _rate_limiter:
        _rate_limiter[client_ip] = []
    timestamps = _rate_limiter[client_ip]

    # Remove timestamps older than the window
    cutoff = now - RATE_LIMIT_WINDOW
    timestamps[:] = [t for t in timestamps if t > cutoff]

    if len(timestamps) >= RATE_LIMIT_MAX:
        return False

    timestamps.append(now)
    return True


# ═══════════════════════════════════════════════════════════════════
# Handler type
# ═══════════════════════════════════════════════════════════════════

HandlerFunc = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


# ═══════════════════════════════════════════════════════════════════
# WebhookReceiver
# ═══════════════════════════════════════════════════════════════════

class WebhookReceiver:
    """The core webhook receiver logic, decoupled from the HTTP framework."""

    def __init__(self, job_queue: Optional[JobQueue] = None, secret: Optional[str] = None):
        self._handlers: Dict[str, HandlerFunc] = {}
        self._failed_events: List[Dict[str, Any]] = []
        self._recent_events: List[Dict[str, Any]] = []
        self._max_recent = 50
        self._secret = secret if secret is not None else WEBHOOK_SECRET
        self._job_queue = job_queue

        self._register_builtin_handlers()
        # Load persisted failed events from disk on startup
        self._load_failed_events()

    # ── Handler registration ─────────────────────────────────────

    def register_handler(self, event_type: str, handler: HandlerFunc) -> None:
        """Register a handler for a specific event_type."""
        self._handlers[event_type] = handler

    def _register_builtin_handlers(self) -> None:
        """Pre-register handlers for scan_request, schedule_update, status_check."""

        def _handle_scan_request(payload: dict) -> Optional[dict]:
            """On scan_request: enqueue a scan job via JobQueue."""
            target = payload.get("target", payload.get("target_asset", "unknown"))
            scan_id = payload.get("scan_id", payload.get("event_id", str(uuid.uuid4())))

            if self._job_queue:
                contract = JobContract.create(
                    tenant_id=payload.get("tenant_id", "default"),
                    mission_id=payload.get("mission_id", scan_id),
                    requested_action="scan",
                    action_type="security_scan",
                    target_asset=target,
                    idempotency_key=f"webhook_scan_{scan_id}",
                    provenance_context={"source": "webhook", "payload": payload},
                )
                record = JobRecord(contract=contract)
                self._job_queue.enqueue(record)

            return {
                "action": "scan_enqueued",
                "target": target,
                "scan_id": scan_id,
            }

        def _handle_schedule_update(payload: dict) -> Optional[dict]:
            """Handle schedule update events."""
            schedule_id = payload.get("schedule_id", "unknown")
            return {
                "action": "schedule_acknowledged",
                "schedule_id": schedule_id,
            }

        def _handle_status_check(payload: dict) -> Optional[dict]:
            """Handle status check events."""
            component = payload.get("component", "unknown")
            return {
                "action": "status_checked",
                "component": component,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        self.register_handler("scan_request", _handle_scan_request)
        self.register_handler("schedule_update", _handle_schedule_update)
        self.register_handler("status_check", _handle_status_check)

    # ── Event processing ─────────────────────────────────────────

    def process_webhook(self, body: bytes, headers: dict) -> Dict[str, Any]:
        """Validate HMAC, parse JSON, dispatch to handler.

        Returns a dict suitable for a JSON response.
        """
        # ── HMAC validation ──
        signature = headers.get("x-signature-256", headers.get("X-Signature-256", ""))
        if not validate_hmac(body, signature, self._secret):
            self._record_failed(
                reason="hmac_validation_failed",
                headers=headers,
            )
            raise HTTPException(
                status_code=403,
                detail={"status": "error", "message": "HMAC signature validation failed"},
            )

        # ── Parse JSON ──
        try:
            payload: dict = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._record_failed(
                reason="json_parse_failed",
                error=str(exc),
            )
            raise HTTPException(
                status_code=400,
                detail={"status": "error", "message": f"Invalid JSON: {exc}"},
            )

        event_type = payload.get("event_type", "")
        event_id = payload.get("event_id", str(uuid.uuid4()))

        if not event_type:
            self._record_failed(
                reason="missing_event_type",
                payload=payload,
            )
            raise HTTPException(
                status_code=400,
                detail={"status": "error", "message": "Missing 'event_type' in payload"},
            )

        # ── Dispatch ──
        handler = self._handlers.get(event_type)
        if not handler:
            # Still record as received, but note no handler
            self._record_recent({
                "event_id": event_id,
                "event_type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "handler_result": None,
                "note": "No handler registered",
            })
            return {
                "status": "received",
                "event_id": event_id,
                "event_type": event_type,
                "handler": None,
                "note": "No handler registered for this event type — acknowledged but not processed",
            }

        try:
            handler_result = handler(payload)
        except Exception as exc:
            self._record_failed(
                event_type=event_type,
                reason="handler_error",
                error=str(exc),
                payload=payload,
            )
            raise HTTPException(
                status_code=500,
                detail={"status": "error", "message": f"Handler error: {exc}"},
            )

        # ── Record success ──
        self._record_recent({
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "handler_result": handler_result,
        })

        return {
            "status": "received",
            "event_id": event_id,
            "event_type": event_type,
            "handler_result": handler_result,
        }

    def health_check(self) -> dict:
        """Return health status."""
        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "handlers": list(self._handlers.keys()),
            "job_queue": "connected" if self._job_queue else "not_configured",
        }

    def status_report(self) -> dict:
        """Return handler list and recent events."""
        return {
            "handlers": list(self._handlers.keys()),
            "handler_count": len(self._handlers),
            "recent_events": self._recent_events,
            "failed_events": self._failed_events,
            "failed_count": len(self._failed_events),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Retry tracking (in-memory + on-disk persistence) ───────────

    def _record_failed(self, **kwargs) -> None:
        """Store a failed event for retry tracking and persist to disk."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        self._failed_events.append(entry)
        self._persist_failed_event(entry)

    def _record_recent(self, entry: dict) -> None:
        """Add to recent events, trimming to max size."""
        self._recent_events.append(entry)
        if len(self._recent_events) > self._max_recent:
            self._recent_events = self._recent_events[-self._max_recent:]

    # ── On-disk persistence of failed events ───────────────────────

    def _persist_failed_event(self, entry: dict) -> None:
        """Append a failed event entry to the JSON file (thread-safe)."""
        try:
            with open(FAILED_EVENTS_PATH, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(json.dumps(entry) + "\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass  # If we can't persist, the in-memory list still holds it

    def _load_failed_events(self) -> None:
        """Read persisted failed events from the JSON file on startup."""
        if not os.path.exists(FAILED_EVENTS_PATH):
            return
        try:
            with open(FAILED_EVENTS_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            self._failed_events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass

    def _clear_failed_events(self) -> None:
        """Clear the failed events file from disk."""
        try:
            if os.path.exists(FAILED_EVENTS_PATH):
                os.remove(FAILED_EVENTS_PATH)
        except OSError:
            pass

    @property
    def failed_events(self) -> List[dict]:
        """Return all failed events."""
        return list(self._failed_events)

    def clear_failed(self) -> None:
        """Clear the failed events list and file (after retry)."""
        self._failed_events.clear()
        self._clear_failed_events()


# ═══════════════════════════════════════════════════════════════════
# FastAPI application factory
# ═══════════════════════════════════════════════════════════════════

def create_app(secret: Optional[str] = None, job_queue: Optional[JobQueue] = None) -> FastAPI:
    """Create and configure the FastAPI webhook application.

    Args:
        secret: HMAC shared secret. Uses WEBHOOK_SECRET env if None.
        job_queue: JobQueue instance. Creates one if None.

    Returns:
        Configured FastAPI app.
    """
    app = FastAPI(title="Vision-M Webhook Receiver", version="1.0.0")

    # ── Create receiver ──
    if job_queue is None:
        store = JobStore()
        lifecycle = JobLifecycleManager()
        job_queue = JobQueue(store, lifecycle)

    receiver = WebhookReceiver(job_queue=job_queue, secret=secret)

    # ── Endpoints ────────────────────────────────────────────────

    @app.post("/webhook")
    async def webhook_endpoint(request: Request):
        """Receive a webhook event. Applies rate limiting, validates HMAC signature, and dispatches."""
        # ── H6: Rate limiting ──
        client_ip = request.client.host if request.client else "unknown"
        if not _check_rate_limit(client_ip):
            return JSONResponse(
                content={"status": "error", "message": "Rate limit exceeded"},
                status_code=429,
            )

        body = await request.body()
        headers = dict(request.headers)
        try:
            result = receiver.process_webhook(body, headers)
            return JSONResponse(content=result, status_code=200)
        except HTTPException:
            raise
        except Exception as exc:
            return JSONResponse(
                content={"status": "error", "message": str(exc)},
                status_code=500,
            )

    @app.post("/webhook/failed/retry")
    async def retry_failed_endpoint():
        """Retry all failed events and clear the failed events list."""
        failed = receiver.failed_events
        count = len(failed)
        retried = []
        for entry in failed:
            if "payload" in entry and "event_type" in entry:
                try:
                    handler = receiver._handlers.get(entry["event_type"])
                    if handler:
                        result = handler(entry["payload"])
                        retried.append({"event": entry, "result": result})
                    else:
                        retried.append({"event": entry, "result": "no_handler"})
                except Exception:
                    retried.append({"event": entry, "result": "retry_failed"})
        receiver.clear_failed()
        return JSONResponse(
            content={
                "status": "retried",
                "count": count,
                "retried": retried,
            },
            status_code=200,
        )

    @app.get("/health")
    async def health_endpoint():
        """Health check."""
        return JSONResponse(content=receiver.health_check(), status_code=200)

    @app.get("/webhook/status")
    async def status_endpoint():
        """Return registered handlers and recent events."""
        return JSONResponse(content=receiver.status_report(), status_code=200)

    # Attach receiver for test access
    app.state.receiver = receiver

    return app


# ═══════════════════════════════════════════════════════════════════
# Standalone entry point
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Vision-M Webhook Receiver")
    parser.add_argument("--port", type=int, default=WEBHOOK_PORT,
                        help=f"Port to listen on (default: {WEBHOOK_PORT})")
    parser.add_argument("--ssl-cert", type=str, default=None,
                        help="Path to SSL certificate file (PEM)")
    parser.add_argument("--ssl-key", type=str, default=None,
                        help="Path to SSL private key file (PEM)")
    args = parser.parse_args()

    app = create_app()

    uvicorn_kwargs = {"host": "0.0.0.0", "port": args.port}
    if args.ssl_cert and args.ssl_key:
        uvicorn_kwargs["ssl_certfile"] = args.ssl_cert
        uvicorn_kwargs["ssl_keyfile"] = args.ssl_key
        print(f"TLS enabled: cert={args.ssl_cert}, key={args.ssl_key}")
    else:
        print("WARNING: TLS not configured. It is recommended to run behind a reverse proxy "
              "(nginx/Caddy) that handles TLS termination. Use --ssl-cert and --ssl-key "
              "to enable TLS directly in uvicorn.")

    uvicorn.run(app, **uvicorn_kwargs)
