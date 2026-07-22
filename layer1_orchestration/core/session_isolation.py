"""
Session Isolation Module — Layer 7 Cross-Session Data Leakage Fix (CF2)

Prevents one session from reading another session's conversation history,
turn journals, run journals, and request dumps.

Usage:
    from layer1_orchestration.core.session_isolation import SessionGuard

    guard = SessionGuard()
    guard.guard_file_access("/data/webui/sessions/other.json")  # raises PermissionError
    if guard.can_access("/data/webui/sessions/my_session.json"):
        ...  # allowed
"""

import os
import logging
from pathlib import Path
from typing import Set, Dict, Optional

logger = logging.getLogger(__name__)

# ── Default paths ────────────────────────────────────────────────────────────
DEFAULT_SESSIONS_DIR = "/data/webui/sessions"
DEFAULT_JOURNAL_DIRS = ("_turn_journal", "_run_journal")

# ── Shared/global files that any session may access ──────────────────────────
SHARED_FILES = frozenset({"_index.json"})


class SessionGuard:
    """
    Guards against cross-session file access.

    On init, scans the sessions directory and builds a mapping of
    session_id → set of owned paths. Only the current session's files
    (identified by HERMES_SESSION_ID) are accessible through this guard.

    Attributes:
        current_session_id: The HERMES_SESSION_ID for this process.
        sessions_dir: Root directory containing session data.
        _session_map: Maps session_id → set of owned file paths (absolute).
        _built: Whether the path map has been populated.
    """

    def __init__(
        self,
        sessions_dir: str = DEFAULT_SESSIONS_DIR,
        session_id: Optional[str] = None,
    ) -> None:
        self.sessions_dir = Path(sessions_dir).resolve()
        self.current_session_id = session_id or os.environ.get("HERMES_SESSION_ID", "")
        self._session_map: Dict[str, Set[str]] = {}
        self._built = False

        if not self.current_session_id:
            logger.warning(
                "SessionGuard: HERMES_SESSION_ID not set — all access denied."
            )
            self._built = True  # empty map, no session owns anything
            return

        self._build_map()

    # ── Internal helpers ─────────────────────────────────────────────────

    def _build_map(self) -> None:
        """Scan the sessions directory and map every session ID to its owned files."""
        if not self.sessions_dir.exists():
            logger.warning(
                "SessionGuard: sessions dir %s not found — no paths guarded.",
                self.sessions_dir,
            )
            self._built = True
            return

        owned: Dict[str, Set[str]] = {}

        # 1. Session JSON files (e.g. /data/webui/sessions/71da87839e3a.json)
        for entry in self.sessions_dir.iterdir():
            if not entry.is_file():
                continue
            if entry.name in SHARED_FILES:
                continue
            if entry.suffix == ".json":
                session_id = entry.stem  # filename without .json
                path_str = str(entry.resolve())
                owned.setdefault(session_id, set()).add(path_str)

        # 2. Journal directories
        for journal_dir_name in DEFAULT_JOURNAL_DIRS:
            journal_dir = self.sessions_dir / journal_dir_name
            if not journal_dir.exists() or not journal_dir.is_dir():
                continue
            for entry in journal_dir.iterdir():
                path_str = str(entry.resolve())
                # Extract session ID from entry name:
                #   _turn_journal/71da87839e3a~13.jsonl  → session_id = "71da87839e3a"
                #   _run_journal/71da87839e3a/             → session_id = "71da87839e3a"
                name = entry.name
                # Remove extension(s) then take the part before '~'
                base = name
                if entry.is_file():
                    base = entry.stem  # e.g. "71da87839e3a~13"
                    if "." in base:  # handle double extensions like .jsonl
                        base = base.split(".")[0]
                # Split on '~' to extract the session ID prefix
                session_id = base.split("~")[0]

                owned.setdefault(session_id, set()).add(path_str)

                # For directories, also add all their contents
                if entry.is_dir():
                    for sub in entry.rglob("*"):
                        owned[session_id].add(str(sub.resolve()))

        self._session_map = owned
        self._built = True
        logger.debug(
            "SessionGuard: mapped %d sessions, current=%s",
            len(self._session_map),
            self.current_session_id,
        )

    def _ensure_built(self) -> None:
        if not self._built:
            self._build_map()

    def _resolve_path(self, path: str) -> str:
        """Resolve a path to an absolute, normalized form."""
        return str(Path(path).resolve())

    def _extract_session_id_from_path(self, path: str) -> Optional[str]:
        """
        Given a resolved path inside sessions_dir, determine which session owns it.
        Returns the session ID or None if unowned/shared.
        """
        resolved = Path(path).resolve()
        try:
            rel = resolved.relative_to(self.sessions_dir)
        except ValueError:
            # Path is outside sessions_dir — not a session file
            return None

        parts = rel.parts
        if len(parts) == 0:
            return None

        first = parts[0]

        # Top-level session JSON: "71da87839e3a.json" → "71da87839e3a"
        if len(parts) == 1 and first.endswith(".json") and first not in SHARED_FILES:
            return Path(first).stem

        # Journal entry: "_turn_journal/71da87839e3a~13.jsonl"
        if len(parts) == 2 and parts[0] in DEFAULT_JOURNAL_DIRS:
            name = parts[1]
            # Strip extensions and '~' suffix
            base = name.split(".")[0]  # "71da87839e3a~13"
            return base.split("~")[0]

        # Journal subdirectory contents: "_run_journal/71da87839e3a/somefile"
        if len(parts) >= 2 and parts[0] in DEFAULT_JOURNAL_DIRS:
            name = parts[1]
            base = name.split(".")[0] if "." in name else name
            return base.split("~")[0]

        return None

    # ── Public API ───────────────────────────────────────────────────────

    def can_access(self, path: str) -> bool:
        """
        Check whether the current session is allowed to access the given path.

        Returns:
            True if the path belongs to the current session or is shared.
            False if the path belongs to a different session.
        """
        if not self.current_session_id:
            return False  # no session → deny all

        resolved = self._resolve_path(path)

        # Fast path: if path is outside sessions_dir, allow (not our concern)
        try:
            Path(resolved).relative_to(self.sessions_dir)
        except ValueError:
            return True  # outside sessions_dir — not a session file

        owner = self._extract_session_id_from_path(resolved)
        if owner is None:
            # Shared file or unrecognized — allow (defensive)
            return True

        return owner == self.current_session_id

    def guard_file_access(self, filepath: str) -> None:
        """
        Raise PermissionError if filepath belongs to a different session.

        Args:
            filepath: Absolute or relative path to check.

        Raises:
            PermissionError: If the file belongs to another session.
        """
        if not self.can_access(filepath):
            owner = self._extract_session_id_from_path(self._resolve_path(filepath))
            raise PermissionError(
                f"Cross-session access denied: '{filepath}' belongs to "
                f"session '{owner}', not current session "
                f"'{self.current_session_id}'."
            )

    def get_current_session_files(self) -> Set[str]:
        """
        Return the set of file paths owned by the current session.

        Returns:
            Set of absolute path strings, or empty set if no session.
        """
        self._ensure_built()
        return self._session_map.get(self.current_session_id, set()).copy()

    def list_sessions(self) -> Set[str]:
        """
        Return all known session IDs.

        Returns:
            Set of session ID strings.
        """
        self._ensure_built()
        return set(self._session_map.keys())

    # ── Singleton convenience ────────────────────────────────────────────

    _instance: Optional["SessionGuard"] = None

    @classmethod
    def get_instance(cls) -> "SessionGuard":
        """Return a cached singleton SessionGuard (lazy init)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (useful for testing)."""
        cls._instance = None
