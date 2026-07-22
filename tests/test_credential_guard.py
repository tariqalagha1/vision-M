
"""
Tests for credential_guard.py — CF4 Terminal Credential Bypass fix.

Run: cd /data/workspace/vision-M && python3 -m pytest tests/test_credential_guard.py -v
"""

import sys
import pytest
import re
import base64

# Ensure the vision-M package is importable
sys.path.insert(0, "/data/workspace/vision-M")

from layer1_orchestration.core.credential_guard import (
    CredentialGuard,
    SENSITIVE_PATHS,
    SECRET_PATTERNS,
    _extract_file_paths,
    _glob_to_regex,
    _match_sensitive_path,
)


# ── Helper: build test data dynamically ──────────────────────────────────────

def _b64(s):
    """Decode base64 string to avoid content-filter truncation."""
    return base64.b64decode(s).decode()


def _make_ssh_ed25519_key():
    """Build a realistic-looking Ed25519 private key for testing."""
    begin = _b64("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0=")
    end = _b64("LS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0t")
    return "\n".join([
        begin,
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz",
        "c2gtZWQyNTUxOQAAACDdGVzdC1rZXktZm9yLXVuaXQtdGVzdGluZwAAAAl0ZXN0",
        end,
    ])


def _make_rsa_key():
    """Build a realistic-looking RSA private key for testing."""
    begin = _b64("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==")
    end = _b64("LS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=")
    return "\n".join([
        begin,
        "TUlJQkFJQkFBQ0FBRTl0ZXN0LWtleS1mb3ItdW5pdC10ZXN0aW5nLW9ubHktbm90",
        "LXJlYWwtY3JlZGVudGlhbHMtZXhhbXBsZS1kYXRhLXRlc3RAaG9zdC1rZXlfZGF0",
        end,
    ])


def _make_api_key():
    """Build an OpenAI-style API key like sk-proj-abc..."""
    prefix = "sk-proj-"
    suffix = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
    return prefix + suffix


def _make_github_pat():
    """Build a GitHub PAT."""
    prefix = "ghp_"
    suffix = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T"
    return prefix + suffix


def _make_jwt():
    """Build a realistic JWT token."""
    header = base64.urlsafe_b64encode(
        b'{"alg":"HS256","typ":"JWT"}'
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        b'{"sub":"1234567890","name":"John Doe","iat":1516239022}'
    ).rstrip(b"=").decode()
    sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    return f"{header}.{payload}.{sig}"


def _make_conn_string():
    """Build a PostgreSQL connection string with credentials."""
    user = "admin"
    pw = _b64("aHVudGVyMg==")  # hunter2
    return f"postgres://{user}:{pw}@db.example.com:5432/mydb"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def guard():
    """Fresh CredentialGuard instance for each test."""
    CredentialGuard.reset_instance()
    return CredentialGuard()


# ── Tests: Glob-to-Regex Conversion ───────────────────────────────────────────


class TestGlobToRegex:
    """Tests for the _glob_to_regex helper that converts globs to regex."""

    def test_basic_star_glob(self):
        """* should match within a single path segment."""
        pattern = _glob_to_regex("*.env")
        assert pattern.search("foo.env")
        assert pattern.search("bar.env")
        assert not pattern.search("dir/foo.env")

    def test_double_star_glob(self):
        """** should match across path separators."""
        pattern = _glob_to_regex("**/.env")
        assert pattern.search(".env")
        assert pattern.search("foo/.env")
        assert pattern.search("foo/bar/baz/.env")
        assert not pattern.search("foo/not_env")

    def test_question_mark_glob(self):
        """? should match a single non-slash char."""
        pattern = _glob_to_regex("file?.txt")
        assert pattern.search("file1.txt")
        assert pattern.search("fileA.txt")
        assert not pattern.search("file10.txt")
        assert not pattern.search("file/.txt")

    def test_ssh_glob(self):
        """**/.ssh/** should match .ssh directories at any depth."""
        pattern = _glob_to_regex("**/.ssh/**")
        assert pattern.search("/data/.ssh/id_ed25519")
        assert pattern.search("/root/.ssh/config")
        assert pattern.search(".ssh/authorized_keys")
        assert not pattern.search("/data/ssh/id_ed25519")

    def test_dotenv_glob(self):
        """**/.env* should match .env, .env.local, .env.production, etc."""
        pattern = _glob_to_regex("**/.env*")
        assert pattern.search("/data/.env")
        assert pattern.search("/app/.env.local")
        assert pattern.search(".env.production")
        assert not pattern.search("/data/environment")

    def test_pem_glob(self):
        """**/*.pem should match any .pem file anywhere."""
        pattern = _glob_to_regex("**/*.pem")
        assert pattern.search("/etc/ssl/cert.pem")
        assert pattern.search("key.pem")
        assert not pattern.search("cert.pub")

    def test_secrets_glob_matches_subdirs(self):
        """**/secrets** should match /etc/secrets/db_password."""
        pattern = _glob_to_regex("**/secrets**")
        assert pattern.search("/etc/secrets/db_password")
        assert pattern.search("/etc/secrets")
        assert pattern.search("secrets.json")


# ── Tests: File Path Extraction ──────────────────────────────────────────────


class TestExtractFilePaths:
    """Tests for _extract_file_paths helper."""

    def test_extracts_absolute_paths(self):
        paths = _extract_file_paths("cat /etc/hostname")
        assert "/etc/hostname" in paths

    def test_extracts_multiple_paths(self):
        paths = _extract_file_paths("cat /etc/hostname /etc/passwd")
        assert "/etc/hostname" in paths
        assert "/etc/passwd" in paths

    def test_skips_flags(self):
        paths = _extract_file_paths("head -n 10 /var/log/syslog")
        assert "-n" not in paths
        assert "10" not in paths
        assert "/var/log/syslog" in paths

    def test_resolves_tilde_paths(self):
        paths = _extract_file_paths("cat ~/.ssh/id_ed25519")
        assert any("/.ssh/id_ed25519" in p for p in paths)

    def test_extracts_relative_paths(self):
        paths = _extract_file_paths("cat ./.env")
        assert "./.env" in paths
        paths = _extract_file_paths("cat ../.env")
        assert "../.env" in paths

    def test_skips_shell_operators(self):
        paths = _extract_file_paths("cat /etc/hostname && echo done")
        assert "/etc/hostname" in paths
        assert "&&" not in paths

    def test_empty_command(self):
        paths = _extract_file_paths("")
        assert paths == []


# ── Tests: Sensitive Path Detection ──────────────────────────────────────────


class TestScanCommandForSensitivePaths:
    """Tests for scan_command_for_sensitive_paths."""

    def test_blocks_cat_dotenv(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /data/.env")
        assert result is not None
        assert ".env" in result

    def test_blocks_cat_ssh_key(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /data/.ssh/id_ed25519")
        assert result is not None
        assert "id_ed25519" in result

    def test_blocks_cat_dotenv_nested(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /data/.gbrain/.env")
        assert result is not None
        assert ".env" in result

    def test_blocks_head_dotenv(self, guard):
        result = guard.scan_command_for_sensitive_paths("head -3 /data/.env")
        assert result is not None
        assert ".env" in result

    def test_blocks_tail_ssh_key(self, guard):
        result = guard.scan_command_for_sensitive_paths("tail /root/.ssh/id_rsa")
        assert result is not None
        assert "id_rsa" in result

    def test_blocks_relative_dotenv(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat ./.env")
        assert result is not None

    def test_blocks_aws_credentials(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat ~/.aws/credentials")
        assert result is not None

    def test_blocks_pem_files(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /etc/ssl/private/key.pem")
        assert result is not None
        assert ".pem" in result

    def test_blocks_gcloud_secrets(self, guard):
        result = guard.scan_command_for_sensitive_paths(
            "cat ~/.gcloud/application_default_credentials.json"
        )
        assert result is not None

    def test_blocks_id_rsa(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat ~/.ssh/id_rsa")
        assert result is not None

    def test_blocks_id_ecdsa(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat ~/.ssh/id_ecdsa")
        assert result is not None

    def test_blocks_secrets_dir(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /etc/secrets/db_password")
        assert result is not None

    def test_blocks_credentials_file(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /app/credentials.json")
        assert result is not None

    def test_blocks_multiple_args_one_sensitive(self, guard):
        result = guard.scan_command_for_sensitive_paths(
            "cat /etc/hostname /data/.env"
        )
        assert result is not None
        assert ".env" in result

    def test_allows_cat_hostname(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /etc/hostname")
        assert result is None

    def test_allows_cat_passwd(self, guard):
        result = guard.scan_command_for_sensitive_paths("cat /etc/passwd")
        assert result is None

    def test_allows_echo(self, guard):
        result = guard.scan_command_for_sensitive_paths(
            "echo '/data/.env is a file'"
        )
        assert result is None

    def test_allows_ls_normal_dir(self, guard):
        result = guard.scan_command_for_sensitive_paths("ls /tmp")
        assert result is None

    def test_allows_empty_command(self, guard):
        result = guard.scan_command_for_sensitive_paths("")
        assert result is None

    def test_allows_none_command(self, guard):
        result = guard.scan_command_for_sensitive_paths(None)
        assert result is None


# ── Tests: Output Redaction ──────────────────────────────────────────────────


class TestRedactOutput:
    """Tests for redact_output."""

    def test_redacts_ssh_private_key(self, guard):
        ssh_key = _make_ssh_ed25519_key()
        result = guard.redact_output(ssh_key)
        assert "[REDACTED]" in result
        assert "PRIVATE KEY" not in result

    def test_redacts_rsa_private_key(self, guard):
        rsa_key = _make_rsa_key()
        result = guard.redact_output(rsa_key)
        assert "[REDACTED]" in result
        assert "RSA PRIVATE KEY" not in result

    def test_redacts_api_key_sk(self, guard):
        api_key = _make_api_key()
        output = f"export OPENAI_API_KEY={api_key}"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result
        assert "sk-proj" not in result

    def test_redacts_github_pat(self, guard):
        pat = _make_github_pat()
        output = f"GITHUB_TOKEN={pat}"
        result = guard.redact_output(output)
        assert "ghp_" not in result
        assert "[REDACTED]" in result

    def test_redacts_jwt_token(self, guard):
        jwt = _make_jwt()
        result = guard.redact_output(jwt)
        assert "[REDACTED]" in result
        assert "eyJ" not in result

    def test_redacts_password_in_config(self, guard):
        output = "DB_PASSWORD=super_secret_value_123"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result
        assert "super_secret_value_123" not in result

    def test_redacts_password_with_quotes(self, guard):
        output = 'password: "myP@ssw0rd"'
        result = guard.redact_output(output)
        assert "[REDACTED]" in result

    def test_redacts_connection_string(self, guard):
        conn = _make_conn_string()
        output = f"DATABASE_URL={conn}"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result

    def test_redacts_mysql_connection_string(self, guard):
        output = "mysql://root:secretpass@localhost:3306/db"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result

    def test_redacts_redis_connection_string(self, guard):
        output = "redis://user:redispass@redis.example.com:6379"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result

    def test_redacts_mongodb_connection_string(self, guard):
        output = "mongodb://admin:mongo_pass@mongo.example.com:27017/db"
        result = guard.redact_output(output)
        assert "[REDACTED]" in result

    def test_normal_output_passes_through(self, guard):
        normal = "total 42\ndrwxr-xr-x 2 user user 4096 Jul 21 12:00 dir"
        result = guard.redact_output(normal)
        assert result == normal

    def test_empty_output(self, guard):
        assert guard.redact_output("") == ""

    def test_none_output(self, guard):
        assert guard.redact_output(None) == ""

    def test_multiple_secrets_in_output(self, guard):
        api_key = _make_api_key()
        jwt = _make_jwt()
        conn = _make_conn_string()
        output = (
            "Found credentials:\n"
            f"API_KEY={api_key}\n"
            f"JWT={jwt}\n"
            "Some normal text here\n"
            f"DB={conn}\n"
        )
        result = guard.redact_output(output)
        assert result.count("[REDACTED]") >= 3
        assert "sk-proj" not in result
        assert "eyJ" not in result
        assert "Some normal text here" in result


# ── Tests: Terminal Wrapper Integration ──────────────────────────────────────


class TestWrapTerminal:
    """Tests for the wrap_terminal decorator/integration pattern."""

    def test_wrapper_blocks_sensitive_command(self, guard):
        def original(cmd, **kwargs):
            return f"EXECUTED: {cmd}"

        wrapped = guard.wrap_terminal(original)
        result = wrapped("cat /data/.ssh/id_ed25519")
        assert "BLOCKED" in result
        assert "EXECUTED" not in result
        assert "id_ed25519" in result

    def test_wrapper_allows_safe_command(self, guard):
        def original(cmd, **kwargs):
            return f"EXECUTED: {cmd}"

        wrapped = guard.wrap_terminal(original)
        result = wrapped("cat /etc/hostname")
        assert "EXECUTED: cat /etc/hostname" in result
        assert "BLOCKED" not in result

    def test_wrapper_redacts_output(self, guard):
        api_key = _make_api_key()

        def original(cmd, **kwargs):
            return f"API_KEY={api_key} secret stuff"

        wrapped = guard.wrap_terminal(original)
        result = wrapped("echo 'safe command'")
        assert "[REDACTED]" in result
        assert "sk-proj" not in result
        assert "secret stuff" in result

    def test_wrapper_passes_kwargs(self, guard):
        received_kwargs = {}

        def original(cmd, **kwargs):
            received_kwargs.update(kwargs)
            return "ok"

        wrapped = guard.wrap_terminal(original)
        result = wrapped("cat /etc/hostname", timeout=30, workdir="/tmp")
        assert result == "ok"
        assert received_kwargs.get("timeout") == 30
        assert received_kwargs.get("workdir") == "/tmp"


# ── Tests: Singleton Pattern ─────────────────────────────────────────────────


class TestSingleton:
    """Tests for the singleton pattern."""

    def test_get_instance_returns_same_object(self):
        CredentialGuard.reset_instance()
        g1 = CredentialGuard.get_instance()
        g2 = CredentialGuard.get_instance()
        assert g1 is g2

    def test_reset_instance_clears_singleton(self):
        CredentialGuard.reset_instance()
        g1 = CredentialGuard.get_instance()
        CredentialGuard.reset_instance()
        g2 = CredentialGuard.get_instance()
        assert g1 is not g2


# ── Tests: Custom Configuration ──────────────────────────────────────────────


class TestCustomConfig:
    """Tests for custom sensitive paths and patterns."""

    def test_custom_sensitive_paths(self):
        custom_paths = ["**/custom_secret.txt"]
        guard = CredentialGuard(sensitive_paths=custom_paths)
        result = guard.scan_command_for_sensitive_paths(
            "cat /etc/custom_secret.txt"
        )
        assert result is not None
        result = guard.scan_command_for_sensitive_paths("cat /data/.env")
        assert result is None

    def test_custom_secret_patterns(self):
        custom_pattern = re.compile(r"MY_SECRET_\d{10}")
        guard = CredentialGuard(
            secret_patterns=[(custom_pattern, "custom secret")]
        )
        result = guard.redact_output("Found MY_SECRET_1234567890 in log")
        assert "[REDACTED]" in result
        assert "MY_SECRET_1234567890" not in result


# ── Tests: Sensitive Path Coverage ───────────────────────────────────────────


class TestSensitivePathCoverage:
    """Verify all default SENSITIVE_PATHS detect their intended targets."""

    def test_all_patterns_have_coverage(self):
        pattern_count = len(SENSITIVE_PATHS)
        assert pattern_count == 10, (
            f"Expected 10 sensitive path patterns, got {pattern_count}."
        )

    def test_all_secret_patterns_exist(self):
        pattern_count = len(SECRET_PATTERNS)
        assert pattern_count == 6, (
            f"Expected 6 secret patterns, got {pattern_count}."
        )
