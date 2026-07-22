"""
Credential Guard — Terminal Credential Bypass Fix (CF4)

Prevents the terminal tool from reading sensitive files that are already
protected by the read_file tool. read_file correctly blocks .env/.ssh files,
but `cat`, `head`, `tail`, and other shell commands could bypass those
protections entirely.

This module provides:
  - Sensitive path detection: block terminal commands that target credential files
  - Output redaction: strip secrets from terminal output if they leak through
  - Terminal wrapper: decorator that applies both protections transparently

Usage:
    from layer1_orchestration.core.credential_guard import CredentialGuard

    guard = CredentialGuard()
    blocked = guard.scan_command_for_sensitive_paths("cat /data/.env")
    # blocked == "/data/.env"

    clean = guard.redact_output("API_KEY=sk-abc123def456...")
    # clean == "API_KEY=[REDACTED]"

    # Wrap the terminal tool:
    safe_terminal = guard.wrap_terminal(original_terminal_func)
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from functools import wraps
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Sensitive Path Globs ─────────────────────────────────────────────────────
#
# Glob patterns matching files that should NEVER be readable via terminal.
# These mirror the protections already in the read_file tool.

SENSITIVE_PATHS: list[str] = [
    "**/.env*",
    "**/.ssh/**",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/*.pem",
    "**/credentials*",
    "**/secrets**",
    "**/.aws/credentials",
    "**/.gcloud/*",
]

# ── Secret Patterns for Output Redaction ─────────────────────────────────────
#
# Regex patterns applied to terminal output to mask secrets that may have
# leaked despite path-level blocks. Each is a (compiled_regex, description) pair.

SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # SSH private key blocks (multi-line, DOTALL needed)
    (
        re.compile(
            r"-----BEGIN[ A-Z]*PRIVATE KEY-----\n?"
            r".*?"
            r"-----END[ A-Z]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "SSH private key",
    ),
    # OpenAI-style API keys (allow hyphens and underscores in key material)
    (
        re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
        "API key (sk-...)",
    ),
    # GitHub personal access tokens
    (
        re.compile(r"ghp_[a-zA-Z0-9]{20,}"),
        "GitHub PAT (ghp_...)",
    ),
    # JWT tokens (three base64url sections separated by dots)
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}"),
        "JWT token",
    ),
    # Passwords / secrets in config files
    (
        re.compile(
            r'(password|passwd|pwd|secret)\s*[=:]\s*["\']?([^"\'\s]{4,})',
            re.IGNORECASE,
        ),
        "password/secret in config",
    ),
    # Database connection strings with embedded credentials
    (
        re.compile(r"(postgres|mysql|redis|mongodb)://[^@\s]+@", re.IGNORECASE),
        "database connection string",
    ),
]

# ── Commands that read files ─────────────────────────────────────────────────
#
# Subset of commands that take file paths as arguments and output content.
# We scan arguments after these commands for sensitive paths.

READ_LIKE_COMMANDS: set[str] = {
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "egrep",
    "rg",
    "strings",
    "xxd",
    "hexdump",
    "od",
    "file",
    "stat",
    "awk",
    "sed",
    "cut",
    "sort",
    "uniq",
    "wc",
    "nl",
    "tac",
    "rev",
    "diff",
    "cmp",
    "comm",
    "tr",
    "paste",
    "join",
    "column",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "cksum",
    "sum",
    "readlink",
    "realpath",
    "dirname",
    "basename",
    "ls",
    "find",
    "du",
    "tree",
    "source",
    ".",
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
}


# ── Glob-to-Regex Conversion ─────────────────────────────────────────────────


def _glob_to_regex(glob_pattern: str) -> re.Pattern:
    """Convert a glob pattern (supporting **) to a compiled regex.

    Handles:
      - **  → .* (match across path separators)
      - *   → [^/]* (match within a single path segment)
      - ?   → [^/] (match single non-slash char)
      - [abc] → literal character class
    """
    i = 0
    regex_parts = []
    n = len(glob_pattern)

    while i < n:
        c = glob_pattern[i]
        if c == "*":
            if i + 1 < n and glob_pattern[i + 1] == "*":
                # ** — match across directories
                # Handle **/ and trailing **
                regex_parts.append(".*")
                i += 2
                # Skip a following / if present (so **/ matches slashes naturally)
                if i < n and glob_pattern[i] == "/":
                    # The .* already matches the /, but we need to make sure
                    # the regex doesn't require a double-match. Just skip the slash
                    # and let .* handle it.
                    i += 1
            else:
                # * — match within a single path segment
                regex_parts.append("[^/]*")
                i += 1
        elif c == "?":
            regex_parts.append("[^/]")
            i += 1
        elif c == ".":
            regex_parts.append(r"\.")
            i += 1
        elif c in "()[]{}^$+\\|":
            regex_parts.append("\\" + c)
            i += 1
        else:
            regex_parts.append(c)
            i += 1

    # Anchor: the glob should match complete path segments
    full_regex = "^" + "".join(regex_parts) + "$"
    return re.compile(full_regex)


# Pre-compile the sensitive path globs at module load
_COMPILED_SENSITIVE_PATHS: list[re.Pattern] = [
    _glob_to_regex(p) for p in SENSITIVE_PATHS
]


# ── File path extraction from commands ───────────────────────────────────────


def _extract_file_paths(command: str) -> list[str]:
    """Extract probable file-path arguments from a shell command string.

    Heuristics:
      - Token starts with /, ./, ../, or ~/
      - And is NOT a command-line flag (doesn't start with -)
      - Skip bare filenames without a path separator (too many false positives)
    """
    paths: list[str] = []
    tokens = command.split()

    for token in tokens:
        # Skip flags
        if token.startswith("-"):
            continue
        # Skip shell operators and redirections
        if token in ("&&", "||", "|", ";", ">", ">>", "<", "<<", "2>", "2>>", "&>"):
            continue
        # Skip assignment-looking tokens (VAR=val)
        if "=" in token and not token.startswith("/"):
            continue

        # Check if it looks like a file path
        if (
            token.startswith("/")
            or token.startswith("./")
            or token.startswith("../")
            or token.startswith("~/")
        ):
            # Strip trailing punctuation that might be shell syntax
            cleaned = token.rstrip(";,|&")
            # Resolve ~ to HOME for matching
            if cleaned.startswith("~/"):
                home = os.path.expanduser("~")
                cleaned = home + cleaned[1:]
            paths.append(cleaned)

    return paths


def _match_sensitive_path(filepath: str) -> Optional[str]:
    """Check if a file path matches any sensitive glob pattern.

    Returns the matching glob pattern description, or None.
    """
    for i, pattern in enumerate(_COMPILED_SENSITIVE_PATHS):
        if pattern.search(filepath):
            return SENSITIVE_PATHS[i]
    return None


# ── CredentialGuard class ────────────────────────────────────────────────────


class CredentialGuard:
    """Detects and blocks sensitive file access via terminal commands,
    and redacts secrets from terminal output that may have leaked.

    Attributes:
        sensitive_paths: List of glob patterns for sensitive files.
        secret_patterns: List of (compiled_regex, description) for output redaction.
        read_commands: Set of commands that can read file contents.
    """

    def __init__(
        self,
        sensitive_paths: Optional[list[str]] = None,
        secret_patterns: Optional[list[tuple[re.Pattern, str]]] = None,
        read_commands: Optional[set[str]] = None,
    ) -> None:
        self.sensitive_paths = sensitive_paths if sensitive_paths is not None else SENSITIVE_PATHS
        self.secret_patterns = (
            secret_patterns if secret_patterns is not None else SECRET_PATTERNS
        )
        self.read_commands = (
            read_commands if read_commands is not None else READ_LIKE_COMMANDS
        )

        # Recompile sensitive paths if overridden
        if sensitive_paths is not None:
            self._compiled_sensitive = [_glob_to_regex(p) for p in self.sensitive_paths]
        else:
            self._compiled_sensitive = _COMPILED_SENSITIVE_PATHS

    # ── Path scanning ────────────────────────────────────────────────────

    def scan_command_for_sensitive_paths(self, command: str) -> Optional[str]:
        """Parse a shell command and check if it targets any sensitive files.

        Extracts file path arguments from read-like commands and checks them
        against the sensitive path globs.

        Args:
            command: The full shell command string to scan.

        Returns:
            The blocked file path if a sensitive file is targeted, or None.
        """
        if not command or not isinstance(command, str):
            return None

        # Extract the command name (first token after env assignments, sudo, etc.)
        cmd_lower = command.strip().split()[0].lower() if command.strip() else ""

        # Only scan read-like commands — other commands (echo, mkdir, ...)
        # can't read file contents even if they touch sensitive paths.
        # Exception: we also check if ANY token matches a sensitive glob
        # to catch edge cases like `source /data/.env` or `bash /data/script.sh`
        # where script.sh itself might not be sensitive but the pattern is.

        paths = _extract_file_paths(command)

        # If the command is read-like, check all extracted paths
        if cmd_lower in self.read_commands:
            for p in paths:
                matched = self._match_sensitive(p)
                if matched:
                    logger.warning(
                        "CredentialGuard: blocked sensitive path %r (pattern %r) "
                        "in command: %r",
                        p,
                        matched,
                        command,
                    )
                    return p

            # Also do a broader scan: check if any token (not just paths)
            # contains a sensitive subpath. This catches relative paths.
            for token in command.split():
                if token.startswith("-") or token.startswith("--"):
                    continue
                matched = self._match_sensitive(token)
                if matched and token not in self.read_commands:
                    logger.warning(
                        "CredentialGuard: blocked sensitive token %r (pattern %r) "
                        "in command: %r",
                        token,
                        matched,
                        command,
                    )
                    return token

        # Even for non-read commands, block if a path argument is a known
        # sensitive path (defense in depth — e.g., `cp`, `mv` touching .env)
        for p in paths:
            matched = self._match_sensitive(p)
            if matched:
                logger.warning(
                    "CredentialGuard: blocked sensitive path %r (pattern %r) "
                    "in command: %r",
                    p,
                    matched,
                    command,
                )
                return p

        return None

    def _match_sensitive(self, filepath: str) -> Optional[str]:
        """Check a file path against compiled sensitive globs."""
        for i, pattern in enumerate(self._compiled_sensitive):
            if pattern.search(filepath):
                return self.sensitive_paths[i]
        return None

    # ── Output redaction ─────────────────────────────────────────────────

    def redact_output(self, output: str) -> str:
        """Redact secrets from terminal output.

        Applies all SECRET_PATTERNS to the output text, replacing matched
        content with ``[REDACTED]``.

        Args:
            output: The raw terminal output (stdout or combined stdout/stderr).

        Returns:
            The output with all detected secrets replaced by [REDACTED].
        """
        if not output or not isinstance(output, str):
            return output or ""

        redacted = output
        for pattern, description in self.secret_patterns:
            if pattern.search(redacted):
                count = len(pattern.findall(redacted))
                redacted = pattern.sub("[REDACTED]", redacted)
                logger.info(
                    "CredentialGuard: redacted %d occurrence(s) of %s",
                    count,
                    description,
                )

        return redacted

    # ── Terminal wrapper ─────────────────────────────────────────────────

    def wrap_terminal(self, original_terminal_func):
        """Decorator that pre-scans commands and redacts output.

        Wraps a terminal execution function to:
          1. Block commands that target sensitive file paths.
          2. Redact secrets from any output that is returned.

        Args:
            original_terminal_func: The original terminal tool function
                accepting (command, **kwargs).

        Returns:
            A wrapped function with the same signature that applies
            credential protection transparently.

        Example:
            from layer1_orchestration.core.credential_guard import CredentialGuard

            guard = CredentialGuard()

            @guard.wrap_terminal
            def my_terminal(command, **kwargs):
                ...  # original implementation

            # Or:
            safe_terminal = guard.wrap_terminal(my_terminal)
        """
        guard = self  # capture reference for closure

        @wraps(original_terminal_func)
        def guarded_terminal(command, **kwargs):
            # 1. Pre-scan: block sensitive path access
            blocked = guard.scan_command_for_sensitive_paths(
                command if isinstance(command, str) else ""
            )
            if blocked:
                return (
                    f"BLOCKED: Command targets sensitive file '{blocked}'. "
                    f"Credential-protected paths cannot be read via terminal. "
                    f"Use the read_file tool with proper redaction instead."
                )

            # 2. Execute the original terminal function
            result = original_terminal_func(command, **kwargs)

            # 3. Redact secrets from the output
            if isinstance(result, str):
                result = guard.redact_output(result)

            return result

        return guarded_terminal

    # ── Singleton convenience ────────────────────────────────────────────

    _instance: Optional["CredentialGuard"] = None

    @classmethod
    def get_instance(cls) -> "CredentialGuard":
        """Return a cached singleton CredentialGuard (lazy init)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (useful for testing)."""
        cls._instance = None
