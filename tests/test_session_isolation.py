"""
Tests for session_isolation.py — CF2 Cross-Session Data Leakage fix.

Run: cd /data/workspace/vision-M && python3 -m pytest tests/test_session_isolation.py -v
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path

# Ensure the vision-M package is importable
sys.path.insert(0, "/data/workspace/vision-M")

from layer1_orchestration.core.session_isolation import (
    SessionGuard,
    SHARED_FILES,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def real_sessions_dir():
    """The actual sessions directory on this system."""
    path = Path("/data/webui/sessions")
    if path.exists():
        return str(path)
    pytest.skip("Real sessions dir not found")


@pytest.fixture
def session_guard_real(real_sessions_dir):
    """SessionGuard backed by the real sessions directory."""
    SessionGuard.reset_instance()
    return SessionGuard(sessions_dir=real_sessions_dir)


@pytest.fixture
def temp_sessions_dir():
    """Create a temporary sessions dir with two fake sessions for testing."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        # Session A: "session_aaa"
        (base / "session_aaa.json").write_text('{"data":"aaa"}')
        (base / "session_bbb.json").write_text('{"data":"bbb"}')
        (base / "_index.json").write_text("[]")

        # Turn journals
        turn_dir = base / "_turn_journal"
        turn_dir.mkdir()
        (turn_dir / "session_aaa~1.jsonl").write_text("line1\n")
        (turn_dir / "session_bbb~2.jsonl").write_text("line2\n")

        # Run journals
        run_dir = base / "_run_journal"
        run_dir.mkdir()
        a_dir = run_dir / "session_aaa"
        a_dir.mkdir()
        (a_dir / "run.json").write_text('{"run":"aaa"}')
        b_dir = run_dir / "session_bbb"
        b_dir.mkdir()
        (b_dir / "run.json").write_text('{"run":"bbb"}')

        yield str(base)


@pytest.fixture
def guard_aaa(temp_sessions_dir):
    """SessionGuard for session_aaa."""
    SessionGuard.reset_instance()
    with tempfile.TemporaryDirectory() as _:  # dummy, we override session_id
        pass
    return SessionGuard(sessions_dir=temp_sessions_dir, session_id="session_aaa")


@pytest.fixture
def guard_bbb(temp_sessions_dir):
    """SessionGuard for session_bbb."""
    SessionGuard.reset_instance()
    return SessionGuard(sessions_dir=temp_sessions_dir, session_id="session_bbb")


# ── Tests: Real sessions directory ────────────────────────────────────────────


class TestRealSessions:
    """Tests against the actual /data/webui/sessions/ directory."""

    def test_smoke_builds_map(self, session_guard_real):
        """SessionGuard should initialise and build a non-empty session map."""
        sessions = session_guard_real.list_sessions()
        assert len(sessions) > 0, "Expected at least one session in the map"
        assert isinstance(sessions, set)

    def test_current_session_id_from_env(self, session_guard_real):
        """Should pick up HERMES_SESSION_ID from the environment."""
        sid = session_guard_real.current_session_id
        assert sid == os.environ["HERMES_SESSION_ID"]
        assert len(sid) > 0

    def test_real_session_owns_its_json(self, session_guard_real):
        """A real session should own its own JSON file."""
        sid = session_guard_real.current_session_id
        json_path = f"/data/webui/sessions/{sid}.json"
        # The current session may or may not have a JSON file yet,
        # but if it does, we should be able to access it.
        if Path(json_path).exists():
            assert session_guard_real.can_access(json_path), (
                f"Session should own its JSON: {json_path}"
            )

    def test_can_access_other_session_json(self, session_guard_real):
        """Should deny access to another session's JSON file."""
        sid = session_guard_real.current_session_id
        # Pick a session file that is NOT the current session
        sessions = session_guard_real.list_sessions()
        other = next((s for s in sessions if s != sid), None)
        if other is None:
            pytest.skip("No other session to test against")

        other_json = f"/data/webui/sessions/{other}.json"
        assert not session_guard_real.can_access(other_json), (
            f"Must deny access to other session: {other_json}"
        )

    def test_guard_raises_on_other_session(self, session_guard_real):
        """guard_file_access should raise PermissionError for other session."""
        sid = session_guard_real.current_session_id
        sessions = session_guard_real.list_sessions()
        other = next((s for s in sessions if s != sid), None)
        if other is None:
            pytest.skip("No other session to test against")

        other_json = f"/data/webui/sessions/{other}.json"
        with pytest.raises(PermissionError, match="Cross-session"):
            session_guard_real.guard_file_access(other_json)

    def test_guard_allows_own_session(self, session_guard_real):
        """guard_file_access should NOT raise for the current session's files."""
        sid = session_guard_real.current_session_id
        own_json = f"/data/webui/sessions/{sid}.json"
        if not Path(own_json).exists():
            pytest.skip(f"Current session JSON not found: {own_json}")
        # Should not raise
        session_guard_real.guard_file_access(own_json)

    def test_shared_index_always_accessible(self, session_guard_real):
        """_index.json should be accessible to all sessions."""
        assert session_guard_real.can_access("/data/webui/sessions/_index.json")

    def test_outside_sessions_dir_always_allowed(self, session_guard_real):
        """Paths outside sessions_dir are not guarded — always allow."""
        assert session_guard_real.can_access("/tmp/something.txt")
        assert session_guard_real.can_access("/etc/passwd")


# ── Tests: Temp directory with known sessions ─────────────────────────────────


class TestTempSessions:
    """Tests using a synthetic sessions directory with session_aaa/session_bbb."""

    def test_can_access_own_json(self, guard_aaa, temp_sessions_dir):
        """Session aaa can access its own JSON."""
        assert guard_aaa.can_access(f"{temp_sessions_dir}/session_aaa.json")

    def test_cannot_access_other_json(self, guard_aaa, temp_sessions_dir):
        """Session aaa cannot access bbb's JSON."""
        assert not guard_aaa.can_access(f"{temp_sessions_dir}/session_bbb.json")

    def test_can_access_own_turn_journal(self, guard_aaa, temp_sessions_dir):
        """Session aaa can access its own turn journal."""
        assert guard_aaa.can_access(
            f"{temp_sessions_dir}/_turn_journal/session_aaa~1.jsonl"
        )

    def test_cannot_access_other_turn_journal(self, guard_aaa, temp_sessions_dir):
        """Session aaa cannot access bbb's turn journal."""
        assert not guard_aaa.can_access(
            f"{temp_sessions_dir}/_turn_journal/session_bbb~2.jsonl"
        )

    def test_can_access_own_run_journal(self, guard_aaa, temp_sessions_dir):
        """Session aaa can access its own run journal directory."""
        assert guard_aaa.can_access(
            f"{temp_sessions_dir}/_run_journal/session_aaa"
        )

    def test_cannot_access_other_run_journal(self, guard_aaa, temp_sessions_dir):
        """Session aaa cannot access bbb's run journal."""
        assert not guard_aaa.can_access(
            f"{temp_sessions_dir}/_run_journal/session_bbb"
        )

    def test_can_access_own_run_journal_file(self, guard_aaa, temp_sessions_dir):
        """Session aaa can access files inside its run journal dir."""
        assert guard_aaa.can_access(
            f"{temp_sessions_dir}/_run_journal/session_aaa/run.json"
        )

    def test_cannot_access_other_run_journal_file(self, guard_aaa, temp_sessions_dir):
        """Session aaa cannot access files inside bbb's run journal."""
        assert not guard_aaa.can_access(
            f"{temp_sessions_dir}/_run_journal/session_bbb/run.json"
        )

    def test_guard_raises_on_other_json(self, guard_aaa, temp_sessions_dir):
        """guard_file_access raises PermissionError for cross-session access."""
        with pytest.raises(PermissionError, match="Cross-session"):
            guard_aaa.guard_file_access(f"{temp_sessions_dir}/session_bbb.json")

    def test_guard_raises_on_other_journal(self, guard_aaa, temp_sessions_dir):
        """guard_file_access raises for cross-session journal access."""
        with pytest.raises(PermissionError, match="Cross-session"):
            guard_aaa.guard_file_access(
                f"{temp_sessions_dir}/_turn_journal/session_bbb~2.jsonl"
            )

    def test_guard_does_not_raise_own_files(self, guard_aaa, temp_sessions_dir):
        """guard_file_access should not raise for own files."""
        guard_aaa.guard_file_access(f"{temp_sessions_dir}/session_aaa.json")
        guard_aaa.guard_file_access(
            f"{temp_sessions_dir}/_turn_journal/session_aaa~1.jsonl"
        )
        guard_aaa.guard_file_access(
            f"{temp_sessions_dir}/_run_journal/session_aaa"
        )

    def test_list_sessions(self, guard_aaa):
        """list_sessions should return both sessions."""
        sessions = guard_aaa.list_sessions()
        assert "session_aaa" in sessions
        assert "session_bbb" in sessions

    def test_get_current_session_files(self, guard_aaa, temp_sessions_dir):
        """get_current_session_files returns only own files."""
        files = guard_aaa.get_current_session_files()
        assert len(files) >= 3  # json + turn journal + run journal dir + contents
        for f in files:
            assert "session_aaa" in f, f"File {f} should belong to session_aaa"
            assert "session_bbb" not in f

    def test_cross_session_bbb_cannot_access_aaa(self, guard_bbb, temp_sessions_dir):
        """Symmetry: bbb cannot access aaa's files."""
        assert not guard_bbb.can_access(f"{temp_sessions_dir}/session_aaa.json")
        assert not guard_bbb.can_access(
            f"{temp_sessions_dir}/_turn_journal/session_aaa~1.jsonl"
        )

    def test_shared_index_accessible(self, guard_aaa, temp_sessions_dir):
        """_index.json is accessible."""
        assert guard_aaa.can_access(f"{temp_sessions_dir}/_index.json")

    def test_outside_dir_always_allowed(self, guard_aaa):
        """Paths outside sessions_dir are always allowed."""
        assert guard_aaa.can_access("/tmp/anything.txt")


# ── Tests: Edge cases ─────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case and error handling tests."""

    def test_no_session_id_env(self, temp_sessions_dir):
        """Guard with no session ID should deny all."""
        # Temporarily unset
        old = os.environ.pop("HERMES_SESSION_ID", None)
        try:
            guard = SessionGuard(sessions_dir=temp_sessions_dir, session_id="")
            assert not guard.can_access(f"{temp_sessions_dir}/session_aaa.json")
        finally:
            if old:
                os.environ["HERMES_SESSION_ID"] = old

    def test_nonexistent_sessions_dir(self):
        """Guard should handle a nonexistent sessions dir gracefully."""
        guard = SessionGuard(
            sessions_dir="/nonexistent/path/sessions",
            session_id="test_session",
        )
        # Should not crash; list should be empty
        assert guard.list_sessions() == set()
        # Outside our dir, so allow
        assert guard.can_access("/tmp/foo.txt")

    def test_singleton(self, temp_sessions_dir):
        """get_instance should return the same guard."""
        SessionGuard.reset_instance()
        g1 = SessionGuard.get_instance()
        g2 = SessionGuard.get_instance()
        assert g1 is g2

    def test_reset_instance(self, temp_sessions_dir):
        """reset_instance should clear the singleton."""
        SessionGuard.reset_instance()
        g1 = SessionGuard.get_instance()
        SessionGuard.reset_instance()
        g2 = SessionGuard.get_instance()
        assert g1 is not g2
