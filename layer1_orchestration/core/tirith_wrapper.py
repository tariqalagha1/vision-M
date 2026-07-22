"""
Tirith Python Fallback Wrapper — in-process replacement for dead Tirith binary.

Provides the same dangerous-pattern detection as the Tirith binary when the
daemon is unavailable. Implements:
  - Dangerous command detection (rm -rf /, sudo, chmod 777, etc.)
  - SSRF protection (block 169.254.x.x, 10.x, 192.168.x, 127.x except loopback)
  - Sensitive file protection (block reads of /etc/shadow, ~/.ssh/, .env files)
  - Fail-closed support (when fail_open=false, unknown/infra failures block)

Usage:
    from layer1_orchestration.core.tirith_wrapper import check_command

    result = check_command("rm -rf /")
    # result == {"action": "block", "findings": [...], "summary": "..."}
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration (overridable via env vars, matches config.yaml schema)
# ---------------------------------------------------------------------------

TIRITH_BIN = os.getenv("TIRITH_BIN", "/data/bin/tirith")
TIRITH_TIMEOUT = int(os.getenv("TIRITH_TIMEOUT", "30"))
TIRITH_FAIL_OPEN = os.getenv("TIRITH_FAIL_OPEN", "false").lower() in ("1", "true", "yes")
TIRITH_ENABLED = os.getenv("TIRITH_ENABLED", "true").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    severity: str  # HIGH, MEDIUM, LOW, INFO
    message: str
    value: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "value": self.value,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Pattern definitions - mirrors Tirith's dangerous pattern catalog
# ---------------------------------------------------------------------------

# Commands that are always dangerous regardless of context
DANGEROUS_PATTERNS: list[tuple[str, str, str, str]] = [
    # (regex, rule_id, severity, message)
    (r"\brm\s+-rf\s+/", "blast_writes_system_path", "HIGH",
     "destructive command targets root filesystem"),
    (r"\brm\s+-rf\s+~", "blast_writes_system_path", "HIGH",
     "destructive command targets home directory tree"),
    (r"\brm\s+-rf\s+/\*", "blast_writes_system_path", "HIGH",
     "destructive command targets root glob"),
    (r"\bchmod\s+777\b", "permissive_chmod", "HIGH",
     "world-writable permissions on files"),
    (r"\bchmod\s+-R\s+777\b", "permissive_chmod_recursive", "HIGH",
     "recursive world-writable permissions"),
    (r"\bsudo\b.*\brm\s+-rf\b", "sudo_destructive", "CRITICAL",
     "privileged destructive command"),
    (r"\b>/\s*dev/\w+", "device_redirect", "HIGH",
     "writing to device files"),
    (r"\bdd\s+if=.*of=/dev/", "dd_device_write", "HIGH",
     "dd writing to raw device"),
    (r"\bmkfs\.", "filesystem_format", "HIGH",
     "filesystem formatting command"),
    (r"(?:^|\s):\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork_bomb", "CRITICAL",
     "shell fork bomb detected"),
    (r"\bcurl\b.*\|\s*(?:ba)?sh\b", "pipe_to_shell", "HIGH",
     "curl piped directly to shell interpreter"),
    (r"\bwget\b.*\|\s*(?:ba)?sh\b", "pipe_to_shell", "HIGH",
     "wget piped directly to shell interpreter"),
    (r"\beval\s+\$", "eval_variable", "HIGH",
     "eval with variable expansion"),
    (r"`[^`]+`", "backtick_substitution", "MEDIUM",
     "backtick command substitution"),
    (r"\$\([^)]+\)", "dollar_substitution", "LOW",
     "dollar-paren command substitution (informational)"),
    (r"\bnc\s+-[lL]\s", "netcat_listener", "HIGH",
     "netcat listener mode"),
    (r"\bwget\b.*-O\s+/(?:etc|tmp)", "wget_system_write", "MEDIUM",
     "wget writing to system directory"),
]

# Sensitive file paths that should never be read by untrusted commands
SENSITIVE_FILE_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"/etc/shadow", "sensitive_file_shadow", "HIGH",
     "attempt to read password shadow file"),
    (r"~?/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys)", "sensitive_file_ssh_key", "CRITICAL",
     "attempt to read SSH private key"),
    (r"~?/\.aws/(?:credentials|config)", "sensitive_file_aws", "HIGH",
     "attempt to read AWS credentials"),
    (r"\.env($|\s)", "sensitive_file_dotenv", "HIGH",
     "attempt to read .env file with secrets"),
    (r"~?/\.git-credentials", "sensitive_file_git_creds", "HIGH",
     "attempt to read git credentials"),
    (r"~?/\.gnupg/", "sensitive_file_gpg", "HIGH",
     "attempt to read GPG keys"),
    (r"/proc/(?:self|\\d+)/", "sensitive_file_proc", "MEDIUM",
     "attempt to read /proc filesystem"),
    (r"/etc/passwd\b", "sensitive_file_passwd", "LOW",
     "attempt to read passwd file"),
]

# Read-like commands that could be used to exfiltrate sensitive files
READ_COMMANDS: set[str] = {"cat", "head", "tail", "less", "more", "grep", "egrep", "rg",
                           "strings", "xxd", "hexdump", "od", "file", "stat"}

# SSRF / Private network blocks
BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("10.0.0.0/8"),       # private A
    ipaddress.ip_network("172.16.0.0/12"),    # private B
    ipaddress.ip_network("192.168.0.0/16"),   # private C
    ipaddress.ip_network("127.0.0.0/8"),      # loopback (block non-localhost)
]

# Allowed loopback addresses
ALLOWED_LOOPBACK = [
    ipaddress.ip_address("127.0.0.1"),
    ipaddress.ip_address("::1"),
]


# ---------------------------------------------------------------------------
# SSRF detection
# ---------------------------------------------------------------------------

def _check_ssrf(command: str) -> list[Finding]:
    """Scan command for SSRF patterns — URLs targeting private/blocked IPs."""
    findings: list[Finding] = []

    # Find all IP addresses in the command
    ipv4_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for match in ipv4_pattern.finditer(command):
        ip_str = match.group(1)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Allow loopback addresses
        if ip in ALLOWED_LOOPBACK:
            continue

        # Check against blocked networks
        for net in BLOCKED_NETWORKS:
            if ip in net:
                findings.append(Finding(
                    rule_id="ssrf_private_ip",
                    severity="HIGH",
                    message=f"SSRF attempt to private network IP: {ip_str}",
                    value=ip_str,
                    detail=f"IP {ip_str} is in blocked range {net}"
                ))
                break

    # Also detect URLs with hostnames that might resolve to private IPs
    url_pattern = re.compile(r'https?://(169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|'
                             r'192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)')
    for match in url_pattern.finditer(command):
        url = match.group(0)
        findings.append(Finding(
            rule_id="ssrf_private_url",
            severity="HIGH",
            message=f"URL targeting private IP range: {url}",
            value=url,
        ))

    return findings


# ---------------------------------------------------------------------------
# Sensitive file detection
# ---------------------------------------------------------------------------

def _check_sensitive_files(command: str) -> list[Finding]:
    """Detect attempts to read sensitive files."""
    findings: list[Finding] = []

    # Find files referenced after read commands
    read_cmd_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(c) for c in READ_COMMANDS) + r')\b\s+([^\s;&|]+)'
    )
    for match in read_cmd_pattern.finditer(command):
        file_path = match.group(2)
        for pattern, rule_id, severity, message in SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, file_path):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    value=file_path,
                    detail=f"Target file: {file_path}"
                ))
                break

    return findings


# ---------------------------------------------------------------------------
# Dangerous command detection
# ---------------------------------------------------------------------------

def _check_dangerous_commands(command: str) -> list[Finding]:
    """Check command against known dangerous patterns."""
    findings: list[Finding] = []

    for pattern, rule_id, severity, message in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                value=command[:200],
            ))

    return findings


# ---------------------------------------------------------------------------
# Native Tirith invocation (preferred when available)
# ---------------------------------------------------------------------------

def _invoke_native_tirith(command: str) -> dict:
    """Try to invoke the native Tirith binary. Returns result or None on failure."""
    if not TIRITH_ENABLED:
        return {"action": "allow", "findings": [], "summary": "tirith disabled"}

    tirith_path = os.path.expanduser(TIRITH_BIN)
    if not os.path.isfile(tirith_path) or not os.access(tirith_path, os.X_OK):
        return {}  # signal fallback needed

    try:
        result = subprocess.run(
            [tirith_path, "check", "--json", "--non-interactive",
             "--shell", "posix", "--", command],
            capture_output=True,
            text=True,
            timeout=TIRITH_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired):
        if not TIRITH_FAIL_OPEN:
            return {"action": "block", "findings": [], "summary": "tirith invocation failed (fail-closed)"}
        return {}  # signal fallback needed

    # Map exit code to action
    exit_code = result.returncode
    if exit_code == 0:
        action = "allow"
    elif exit_code == 1:
        action = "block"
    elif exit_code == 2:
        action = "warn"
    else:
        if not TIRITH_FAIL_OPEN:
            return {"action": "block", "findings": [],
                    "summary": f"tirith exit code {exit_code} (fail-closed)"}
        return {"action": "allow", "findings": [],
                "summary": f"tirith exit code {exit_code} (fail-open)"}

    # Parse JSON
    findings = []
    summary = ""
    try:
        import json
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        findings = data.get("findings", [])
        summary = data.get("summary", "") or ""
    except Exception:
        if action == "block":
            summary = "security issue detected"

    return {"action": action, "findings": findings, "summary": summary}


# ---------------------------------------------------------------------------
# Python fallback scan
# ---------------------------------------------------------------------------

def _python_fallback_check(command: str) -> dict:
    """Run all Python-based pattern checks."""
    all_findings: list[Finding] = []

    all_findings.extend(_check_dangerous_commands(command))
    all_findings.extend(_check_sensitive_files(command))
    all_findings.extend(_check_ssrf(command))

    findings_dicts = [f.to_dict() for f in all_findings]

    if not all_findings:
        return {"action": "allow", "findings": [], "summary": "no issues (python fallback)"}

    # Determine overall action based on highest severity
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    max_sev = max(severity_order.get(f.severity, 0) for f in all_findings)

    if max_sev >= 3:  # HIGH or CRITICAL
        action = "block"
    elif max_sev >= 2:  # MEDIUM
        action = "warn"
    else:
        action = "allow"

    summary = f"python fallback: {len(all_findings)} finding(s) — "
    summary += ", ".join(f"{f.rule_id}: {f.message}" for f in all_findings[:5])
    if len(all_findings) > 5:
        summary += f" ... and {len(all_findings) - 5} more"

    return {"action": action, "findings": findings_dicts, "summary": summary}


# ---------------------------------------------------------------------------
# Main API
# ---------------------------------------------------------------------------

def check_command(command: str) -> dict:
    """Check a shell command for security issues.

    Runs both native Tirith AND Python fallback patterns, merging results.
    The strictest verdict wins: if either says block, the command is blocked.

    Returns:
        {"action": "allow"|"warn"|"block", "findings": [...], "summary": str}
    """
    if not TIRITH_ENABLED:
        return {"action": "allow", "findings": [], "summary": "tirith disabled"}

    # Run both native Tirith and Python fallback
    native_result = _invoke_native_tirith(command)
    python_result = _python_fallback_check(command)

    # Merge findings
    all_findings = []
    all_findings.extend(python_result.get("findings", []))
    if native_result:
        all_findings.extend(native_result.get("findings", []))

    # Determine strictest action: block > warn > allow
    action_order = {"block": 3, "warn": 2, "allow": 1}
    native_action = native_result.get("action", "allow") if native_result else "allow"
    python_action = python_result.get("action", "allow")

    best_action = "allow"
    best_score = 1
    for act in (native_action, python_action):
        score = action_order.get(act, 0)
        if score > best_score:
            best_score = score
            best_action = act

    # Build summary
    parts = []
    if native_result:
        native_summary = native_result.get("summary", "")
        if native_summary:
            parts.append(f"native: {native_summary}")
    python_summary = python_result.get("summary", "")
    if python_summary:
        parts.append(f"python: {python_summary}")
    summary = " | ".join(parts) if parts else ""

    return {"action": best_action, "findings": all_findings, "summary": summary}


def status() -> dict:
    """Return Tirith protection status."""
    tirith_path = os.path.expanduser(TIRITH_BIN)
    native_available = os.path.isfile(tirith_path) and os.access(tirith_path, os.X_OK)
    daemon_alive = False

    if native_available:
        try:
            result = subprocess.run(
                [tirith_path, "daemon", "status"],
                capture_output=True, text=True, timeout=3
            )
            # Tirith writes status to stderr
            combined = (result.stdout + result.stderr).lower()
            daemon_alive = result.returncode == 0 and "running" in combined
        except Exception:
            pass

    return {
        "enabled": TIRITH_ENABLED,
        "native_binary_available": native_available,
        "native_binary_path": tirith_path,
        "daemon_running": daemon_alive,
        "fail_open": TIRITH_FAIL_OPEN,
        "timeout": TIRITH_TIMEOUT,
        "protection": "on" if (native_available and daemon_alive) or not TIRITH_FAIL_OPEN else "degraded",
        "mode": "native" if (native_available and daemon_alive) else "python_fallback",
    }
