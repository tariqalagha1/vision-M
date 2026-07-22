#!/usr/bin/env python3
"""
Command Classifier — Dangerous Command Detection for Layer 2 Approval System

This module provides a CommandClassifier that categorizes shell commands into
three risk levels:
  - hardline_blocked: Unconditional blocks (mkfs, shutdown, dd to devices, etc.)
  - requires_approval: Dangerous commands that must trigger manual approval
  - safe: Benign commands or safe variants (help/version flags only)

BACKGROUND:
  The existing command_filter.py focuses on shell *injection patterns*
  (metacharacters, chaining, pipes). This classifier complements it by
  focusing on specific dangerous *commands* (rm, chmod, curl, wget, pip, dd,
  systemctl, kill) that execute without triggering the approval system.

  approvals.mode=manual is correctly set but the classifier under-triggers:
  only mkfs and shutdown are hardline-blocked. Common dangerous commands
  like rm, chmod, curl execute freely.

Architecture:
  - HARDLINE_BLOCKED: tuple of (substring_or_regex, description)
  - DANGEROUS_REQUIRING_APPROVAL: tuple of (substring_or_regex, rule_name)
  - SAFE_VARIANTS: tuple of (substring_or_regex, description)
  
  classify() runs through all three levels in priority order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ── Hardline Blocklist ───────────────────────────────────────────────────────
#
# Commands that must NEVER execute — no approval can override these.
# Each entry is (substring_or_regex_pattern, description_in_reason_message).
#
# NOTE: Some entries are regex patterns (starting with ^ or containing \\b).
# The classifier first checks for literal substring matches, then falls back
# to regex matching.

HARDLINE_BLOCKED: list[tuple[str, str]] = [
    # Filesystem formatting (must be matched first, before broader mkfs check)
    ("mkfs", "format filesystem (mkfs)"),

    # Shutdown / reboot / halt / poweroff (all variants)
    ("shutdown", "system shutdown/reboot"),
    ("reboot", "system reboot"),
    ("halt", "system halt"),
    ("poweroff", "system poweroff"),
    ("init 0", "system shutdown via init 0"),
    ("init 6", "system reboot via init 6"),

    # dd to block devices — unconditional destruction
    ("dd if=/dev/zero of=/dev/", "dd: destructive write to block device"),
    ("dd if=/dev/urandom of=/dev/", "dd: destructive write to block device"),
    # Broader dd to /dev pattern (regex)
    (r"\bdd\b.*\bof=/dev/[a-z]+", "dd: write to block device"),

    # Fork bomb patterns
    (":(){ :|:& };:", "fork bomb"),
]


# ── Dangerous Commands Requiring Approval ────────────────────────────────────
#
# Commands that are dangerous but can be executed with manual user approval.
# Each entry is (substring_or_regex_pattern, rule_name).

DANGEROUS_REQUIRING_APPROVAL: list[tuple[str, str]] = [
    # rm — file removal, especially recursive/force
    (r"\brm\b(?:\s+-[a-zA-Z]*[rf][a-zA-Z]*|\s+--)", "rm: recursive/force file removal"),
    (r"\brm\b", "rm: file removal"),

    # chmod — permission changes, especially 777 or recursive
    (r"\bchmod\b(?:\s+.*\b777\b|\s+-[a-zA-Z]*R)", "chmod: dangerous permission change"),
    (r"\bchmod\b", "chmod: permission change"),

    # chown — ownership change
    (r"\bchown\b", "chown: ownership change"),

    # curl — downloading to file or piping to shell
    (r"\bcurl\b.*\b(?:-o\b|-O\b|\|\s*(?:ba)?sh\b)", "curl: downloading to file or piping to shell"),
    (r"\bcurl\b.*\b(?:-s\S*|\|\s*)", "curl: suspicious usage"),
    (r"\bcurl\b", "curl: network request"),

    # wget — downloading to file
    (r"\bwget\b.*\b-O\b", "wget: downloading to file"),
    (r"\bwget\b", "wget: downloading"),

    # pip install / uninstall
    (r"\bpip3?\s+install\b", "pip: package installation"),
    (r"\bpip3?\s+uninstall\b", "pip: package uninstallation"),

    # npm install -g
    (r"\bnpm\s+install\s+-g\b", "npm: global package installation"),

    # systemctl — service management
    (r"\bsystemctl\s+(start|stop|restart|enable|disable|mask|unmask)\b",
     "systemctl: service management"),

    # kill / pkill — process termination
    (r"\bkill\s+-9\b", "kill: force kill with SIGKILL"),
    (r"\bkill\b", "kill: process termination"),
    (r"\bpkill\b", "pkill: process termination by name"),

    # iptables — firewall modification
    (r"\biptables\b", "iptables: firewall rule modification"),
]


# ── Safe Variants ────────────────────────────────────────────────────────────
#
# Safe variants of dangerous commands that should NOT trigger approval.
# Checked FIRST for any command that matches a dangerous pattern.
# If the command matches a safe variant, it is classified as "safe".

SAFE_VARIANTS: list[tuple[str, str, str]] = [
    # (substring_or_regex, description, associated_dangerous_command)
    # rm --help / rm --version
    (r"^\brm\s+--help\b", "rm help", "rm"),
    (r"^\brm\s+--version\b", "rm version", "rm"),

    # chmod --help / chmod --version
    (r"^\bchmod\s+--help\b", "chmod help", "chmod"),
    (r"^\bchmod\s+--version\b", "chmod version", "chmod"),

    # chown --help / chown --version
    (r"^\bchown\s+--help\b", "chown help", "chown"),
    (r"^\bchown\s+--version\b", "chown version", "chown"),

    # curl --version / curl --help
    (r"^\bcurl\s+--version\b", "curl version", "curl"),
    (r"^\bcurl\s+--help\b", "curl help", "curl"),

    # wget --version / wget --help
    (r"^\bwget\s+--version\b", "wget version", "wget"),
    (r"^\bwget\s+--help\b", "wget help", "wget"),

    # pip --version / pip --help
    (r"^\bpip3?\s+--version\b", "pip version", "pip"),
    (r"^\bpip3?\s+--help\b", "pip help", "pip"),

    # systemctl --version / systemctl --help
    (r"^\bsystemctl\s+--version\b", "systemctl version", "systemctl"),
    (r"^\bsystemctl\s+--help\b", "systemctl help", "systemctl"),

    # kill --help / kill -l (list signals)
    (r"^\bkill\s+--help\b", "kill help", "kill"),
    (r"^\bkill\s+-l\b", "kill list signals", "kill"),

    # pkill --version / pkill --help
    (r"^\bpkill\s+--version\b", "pkill version", "pkill"),
    (r"^\bpkill\s+--help\b", "pkill help", "pkill"),

    # iptables --version / iptables --help
    (r"^\biptables\s+--version\b", "iptables version", "iptables"),
    (r"^\biptables\s+--help\b", "iptables help", "iptables"),

    # dd --version / dd --help
    (r"^\bdd\s+--version\b", "dd version", "dd"),
    (r"^\bdd\s+--help\b", "dd help", "dd"),

    # npm --version / npm --help
    (r"^\bnpm\s+--version\b", "npm version", "npm"),
    (r"^\bnpm\s+--help\b", "npm help", "npm"),
]


# ── Result Dataclass ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ClassificationResult:
    """Result of command classification.

    Attributes:
        level: One of "hardline_blocked", "requires_approval", or "safe".
        command: The original command string.
        reason: Human-readable explanation (for blocked/approval).
        matched_rule: The rule name that matched (for requires_approval).
    """
    level: str
    command: str
    reason: str = ""
    matched_rule: str = ""

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict representation."""
        result: dict = {
            "level": self.level,
            "command": self.command,
        }
        if self.reason:
            result["reason"] = self.reason
        if self.matched_rule:
            result["matched_rule"] = self.matched_rule
        return result


# ── CommandClassifier ────────────────────────────────────────────────────────

class CommandClassifier:
    """Classify shell commands into risk levels for the approval system.

    Usage:
        >>> classifier = CommandClassifier()
        >>> result = classifier.classify("rm -rf /tmp/test")
        >>> result.level
        'requires_approval'
        >>> result = classifier.classify("shutdown -h now")
        >>> result.level
        'hardline_blocked'
        >>> result = classifier.classify("ls -la")
        >>> result.level
        'safe'
    """

    def __init__(self):
        """Initialize the classifier with compiled regex patterns."""
        # Pre-compile regex patterns for performance
        self._hardline_re: list[tuple[re.Pattern, str]] = []
        self._hardline_substrings: list[tuple[str, str]] = []

        for pattern, description in HARDLINE_BLOCKED:
            if _is_regex_pattern(pattern):
                self._hardline_re.append((re.compile(pattern, re.IGNORECASE), description))
            else:
                self._hardline_substrings.append((pattern.lower(), description))

        self._dangerous_re: list[tuple[re.Pattern, str]] = []

        for pattern, rule_name in DANGEROUS_REQUIRING_APPROVAL:
            self._dangerous_re.append((re.compile(pattern, re.IGNORECASE), rule_name))

        self._safe_variants_re: list[tuple[re.Pattern, str, str]] = []

        for pattern, description, associated in SAFE_VARIANTS:
            self._safe_variants_re.append(
                (re.compile(pattern, re.IGNORECASE), description, associated)
            )

    def classify(self, command: str) -> ClassificationResult:
        """Classify a command string into a risk level.

        Args:
            command: The full command string to classify.

        Returns:
            ClassificationResult with level and metadata.

        Checks are performed in priority order:
          1. Safe variants (help/version flags override dangerous matches)
          2. Hardline blocked (unconditional blocks, cannot be overridden)
          3. Dangerous requiring approval (triggers manual approval)
          4. Default: safe
        """
        # Reject non-string inputs
        if not isinstance(command, str):
            return ClassificationResult(
                level="safe",
                command=str(command),
                reason=f"non-string input of type {type(command).__name__} — classified as safe fallback",
            )

        cmd = command.strip()
        if not cmd:
            return ClassificationResult(
                level="safe",
                command=command,
                reason="empty command",
            )

        cmd_lower = cmd.lower()

        # ── Priority 1: Check safe variants FIRST ───────────────────────
        # Even if a command looks dangerous (e.g., "rm --help"), if it
        # matches a safe variant, it's safe.
        for pattern_re, description, associated_cmd in self._safe_variants_re:
            if pattern_re.search(cmd):
                return ClassificationResult(
                    level="safe",
                    command=command,
                    reason=f"safe variant: {description}",
                )

        # ── Priority 2: Check hardline blocks ──────────────────────────
        # Literal substring matches first (faster)
        for substr, description in self._hardline_substrings:
            if substr in cmd_lower:
                return ClassificationResult(
                    level="hardline_blocked",
                    command=command,
                    reason=f"BLOCKED (hardline): {description}. "
                           f"This command is on the unconditional blocklist "
                           f"and cannot be executed via the agent.",
                )

        # Regex matches for complex patterns
        for pattern_re, description in self._hardline_re:
            if pattern_re.search(cmd):
                return ClassificationResult(
                    level="hardline_blocked",
                    command=command,
                    reason=f"BLOCKED (hardline): {description}. "
                           f"This command is on the unconditional blocklist "
                           f"and cannot be executed via the agent.",
                )

        # ── Priority 3: Check dangerous commands requiring approval ────
        for pattern_re, rule_name in self._dangerous_re:
            if pattern_re.search(cmd):
                return ClassificationResult(
                    level="requires_approval",
                    command=command,
                    matched_rule=rule_name,
                    reason=f"DANGEROUS: {rule_name}. "
                           f"This command requires manual user approval before execution.",
                )

        # ── Priority 4: Everything else is safe ────────────────────────
        return ClassificationResult(
            level="safe",
            command=command,
        )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_regex_pattern(pattern: str) -> bool:
    """Determine if a pattern string is a regex (not a plain substring)."""
    regex_indicators = [
        r"\b",  # word boundary
        r"\s",  # whitespace
        r"^",   # start anchor
        r"$",   # end anchor
        r"|",   # alternation
        r"[a-z]",  # character class
        r"\d",  # digit
        r"\w",  # word char
        r"\S",  # non-whitespace
        r"(?:",  # non-capturing group
        r"*",   # quantifier (not literal)
        r"+",   # quantifier
        r"?",   # quantifier / optional
    ]
    return any(indicator in pattern for indicator in regex_indicators)
