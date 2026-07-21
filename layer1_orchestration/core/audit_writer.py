"""
Audit persistence — writes discovery events to a JSONL audit log.

All writes are append-only; the module is designed for reliable, simple
persistence without external dependencies.
"""

import json
import os
import threading

# Path to the audit JSONL file.
# Defaults to a file in the project root; override with AUDIT_LOG_PATH env var.
_DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "audit.jsonl",
)
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", _DEFAULT_LOG_PATH)

_write_lock = threading.Lock()


def write_audit_event(event_dict: dict) -> None:
    """Append a single event as a JSON line to the audit log.

    Thread-safe via an internal lock.  Silent on failure (exceptions are
    swallowed so the caller never breaks).

    Args:
        event_dict: A serialisable dict (usually DiscoveryEvent.to_dict()).
    """
    try:
        line = json.dumps(event_dict, default=str) + "\n"
        with _write_lock:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass  # best-effort persistence — never break the caller
