"""Tests for APIAuth CLI keystore, keygen, and verify modules."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from apiauth.keystore import Keystore
from apiauth.keygen import (
    create_api_key_entry,
    create_jwt_entry,
    generate_api_key,
    rotate_key,
    rotate_jwt,
    verify_api_key,
    verify_jwt_token,
)
from apiauth.verify import check_expiry
from apiauth.cli import cli


def _extract_json(text: str) -> str:
    """Extract JSON array or object from output that may have stderr mixed in."""
    import re
    match = re.search(r'(\[.*\]|\{.*\})', text.strip(), re.DOTALL)
    return match.group(1) if match else text


@pytest.fixture
def runner():
    """Provide a Click CliRunner."""
    from click.testing import CliRunner
    return CliRunner()


@pytest.fixture
def tmp_keystore():
    """Create a temporary keystore for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ks = Keystore(tmpdir)
        yield ks


class TestGenerateAPIKey:
    def test_generates_unique_keys(self):
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_key_format(self):
        key = generate_api_key(prefix="test")
        assert key.startswith("test_")
        assert len(key) > 20

    def test_default_prefix(self):
        key = generate_api_key()
        assert key.startswith("ak_")


class TestKeystore:
    def test_init_creates_master_key(self, tmp_keystore):
        key_file = tmp_keystore.key_dir / "master.key"
        assert key_file.exists()
        assert len(key_file.read_bytes()) == 32  # AES-256 = 32 bytes

    def test_put_and_get(self, tmp_keystore):
        tmp_keystore.put("test1", {"name": "Test Key", "type": "api_key"})
        entry = tmp_keystore.get("test1")
        assert entry is not None
        assert entry["name"] == "Test Key"

    def test_get_nonexistent(self, tmp_keystore):
        assert tmp_keystore.get("nope") is None

    def test_delete(self, tmp_keystore):
        tmp_keystore.put("del_me", {"name": "Delete Me"})
        assert tmp_keystore.delete("del_me") is True
        assert tmp_keystore.get("del_me") is None
        assert tmp_keystore.delete("del_me") is False

    def test_list_keys(self, tmp_keystore):
        tmp_keystore.put("a", {"name": "A", "service": "svc1", "created_at": "2024-01-01"})
        tmp_keystore.put("b", {"name": "B", "service": "svc2", "created_at": "2024-01-02"})
        assert len(tmp_keystore.list_keys()) == 2
        assert len(tmp_keystore.list_keys(service="svc1")) == 1

    def test_get_stats(self, tmp_keystore):
        tmp_keystore.put("a", {"name": "A", "service": "svc1"})
        tmp_keystore.put("b", {"name": "B", "service": "svc1"})
        stats = tmp_keystore.get_stats()
        assert stats["total_keys"] == 2
        assert stats["by_service"]["svc1"] == 2

    def test_persistence(self, tmp_keystore):
        """Verify encrypted persistence survives re-init."""
        tmp_keystore.put("persist", {"name": "Persistent", "service": "test"})
        key_dir = tmp_keystore.key_dir

        ks2 = Keystore(key_dir)
        entry = ks2.get("persist")
        assert entry is not None
        assert entry["name"] == "Persistent"

    def test_master_key_reused(self, tmp_keystore):
        """Verify same master key is reused, not regenerated."""
        key_path = tmp_keystore.key_dir / "master.key"
        first_mtime = key_path.stat().st_mtime

        ks2 = Keystore(tmp_keystore.key_dir)
        assert key_path.stat().st_mtime == first_mtime  # Not overwritten


class TestCreateAPIKey:
    def test_create_api_key_entry(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "My Key", "api-gateway", expiry_days=90)
        assert result["name"] == "My Key"
        assert result["service"] == "api-gateway"
        assert result["type"] == "api_key"
        assert "api_key" in result  # Plaintext returned
        assert result["expires_at"] is not None
        assert result["revoked"] is False

    def test_create_with_rate_limit(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "Rated", "api", rate_limit=100)
        assert result["rate_limit"] == 100

    def test_no_expiry(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "No Expiry", "api")
        assert result.get("expires_at") is None

    def test_key_hash_matches(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "Hash Check", "api")
        api_key = result["api_key"]
        expected_hash = hashlib.sha256(api_key.encode()).hexdigest()
        stored = tmp_keystore.get(result["id"])
        assert stored["key_hash"] == expected_hash


class TestCreateJWT:
    def test_create_jwt(self, tmp_keystore):
        result = create_jwt_entry(tmp_keystore, "My JWT", "auth-service", expiry_days=30)
        assert result["name"] == "My JWT"
        assert result["service"] == "auth-service"
        assert result["type"] == "jwt"
        assert "token" in result
        assert result["token"].count(".") == 2  # JWT has 3 parts

    def test_custom_claims(self, tmp_keystore):
        result = create_jwt_entry(
            tmp_keystore, "Claims", "api", claims={"role": "admin", "scope": "read:users"}
        )
        stored = tmp_keystore.get(result["id"])
        assert stored["claims"]["role"] == "admin"
        assert stored["claims"]["scope"] == "read:users"

    def test_jwt_expiry(self, tmp_keystore):
        result = create_jwt_entry(tmp_keystore, "Expiry", "api", expiry_days=7)
        assert result["expires_at"] is not None
        stored = tmp_keystore.get(result["id"])
        assert stored["expires_at"] is not None


class TestRotate:
    def test_rotate_api_key(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "Rotatable", "api")
        orig_key = result["api_key"]
        orig_id = result["id"]

        rotated = rotate_key(tmp_keystore, orig_id)
        assert rotated is not None
        assert rotated["api_key"] != orig_key
        assert rotated["version"] == 2

        stored = tmp_keystore.get(orig_id)
        assert stored["previous_hash"] == hashlib.sha256(orig_key.encode()).hexdigest()

    def test_rotate_jwt(self, tmp_keystore):
        result = create_jwt_entry(tmp_keystore, "Rotatable JWT", "api")
        orig_token = result["token"]
        orig_id = result["id"]

        rotated = rotate_jwt(tmp_keystore, orig_id)
        assert rotated is not None
        assert rotated["token"] != orig_token
        assert rotated["version"] == 2

    def test_rotate_nonexistent(self, tmp_keystore):
        assert rotate_key(tmp_keystore, "nope") is None
        assert rotate_jwt(tmp_keystore, "nope") is None


class TestRevoke:
    def test_revoke_key(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "Revocable", "api")
        entry = tmp_keystore.get(result["id"])
        assert entry["revoked"] is False

        entry["revoked"] = True
        tmp_keystore.put(result["id"], entry)
        updated = tmp_keystore.get(result["id"])
        assert updated["revoked"] is True

    def test_revoke_nonexistent(self, tmp_keystore):
        assert tmp_keystore.delete("nothing") is False


class TestVerifyAPIKey:
    def test_verify_valid_key(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "VerifyMe", "api")
        api_key = result["api_key"]

        v = verify_api_key(tmp_keystore, api_key)
        assert v is not None
        assert v["status"] == "valid"
        assert v["id"] == result["id"]

    def test_verify_revoked_key(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "RevokeMe", "api")
        api_key = result["api_key"]
        entry = tmp_keystore.get(result["id"])
        entry["revoked"] = True
        tmp_keystore.put(result["id"], entry)

        v = verify_api_key(tmp_keystore, api_key)
        assert v is not None
        assert v["status"] == "revoked"

    def test_verify_unknown_key(self, tmp_keystore):
        v = verify_api_key(tmp_keystore, "ak_totallyfake12345")
        assert v is None

    def test_verify_expired_key(self, tmp_keystore):
        result = create_api_key_entry(tmp_keystore, "Expired", "api", expiry_days=-1)
        api_key = result["api_key"]

        # Manually set expires_at to past
        entry = tmp_keystore.get(result["id"])
        entry["expires_at"] = "2020-01-01T00:00:00Z"
        tmp_keystore.put(result["id"], entry)

        v = verify_api_key(tmp_keystore, api_key)
        assert v is not None
        assert v["status"] == "expired"


class TestVerifyJWT:
    def test_verify_valid_jwt(self, tmp_keystore):
        result = create_jwt_entry(tmp_keystore, "VerifyJWT", "auth")
        token = result["token"]

        v = verify_jwt_token(tmp_keystore, token)
        assert v is not None
        assert v["status"] == "valid"

    def test_verify_revoked_jwt(self, tmp_keystore):
        result = create_jwt_entry(tmp_keystore, "RevokeJWT", "auth")
        entry = tmp_keystore.get(result["id"])
        entry["revoked"] = True
        tmp_keystore.put(result["id"], entry)

        v = verify_jwt_token(tmp_keystore, result["token"])
        assert v is not None
        assert v["status"] == "revoked"

    def test_verify_invalid_jwt(self, tmp_keystore):
        v = verify_jwt_token(tmp_keystore, "not.a.jwt")
        assert v is None


class TestCheckExpiry:
    def test_no_expiry(self):
        assert check_expiry({}) is None

    def test_expired(self):
        result = check_expiry({"expires_at": "2020-01-01T00:00:00Z"})
        assert result == "expired"

    def test_not_expired(self):
        result = check_expiry({"expires_at": "2099-01-01T00:00:00Z"})
        assert result is None

    def test_expiring_soon(self):
        import datetime
        soon = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)).isoformat()[:23] + "Z"
        result = check_expiry({"expires_at": soon})
        assert result == "expiring"


class TestCLIIntegration:
    """Test CLI commands via Click CliRunner."""

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "0.2.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "APIAuth" in result.output
        assert "generate" in result.output
        assert "list" in result.output
        assert "rotate" in result.output
        assert "revoke" in result.output

    def test_generate_api_key(self, runner, tmp_keystore):
        result = runner.invoke(
            cli,
            ["--key-dir", str(tmp_keystore.key_dir), "generate", "api-key",
             "--name", "TestKey", "--service", "api-gateway", "--expiry-days", "90"],
        )
        assert result.exit_code == 0
        assert "TestKey" in result.output
        assert "api-gateway" in result.output
        assert "ak_" in result.output or "API key" in result.output

    def test_generate_jwt(self, runner, tmp_keystore):
        result = runner.invoke(
            cli,
            ["--key-dir", str(tmp_keystore.key_dir), "generate", "jwt",
             "--name", "MyJWT", "--service", "auth", "--expiry-days", "30"],
        )
        assert result.exit_code == 0
        assert "MyJWT" in result.output
        assert "JWT" in result.output

    def test_list_keys(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "Key1", "svc1")
        create_jwt_entry(tmp_keystore, "Token1", "svc2")

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "list"])
        assert result.exit_code == 0
        assert "Key1" in result.output
        assert "Token1" in result.output

    def test_list_filter_by_service(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "Key1", "svc1")
        create_api_key_entry(tmp_keystore, "Key2", "svc2")

        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "list", "--service", "svc1"]
        )
        assert result.exit_code == 0
        assert "Key1" in result.output
        assert "Key2" not in result.output

    def test_list_json_output(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "JsonKey", "api")
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "list", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert isinstance(data, list)

    def test_show_key(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "ShowMe", "api")
        key_id = entry["id"]

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "show", key_id])
        assert result.exit_code == 0
        assert "ShowMe" in result.output

    def test_show_nonexistent(self, runner, tmp_keystore):
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "show", "nonexistent"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_rotate_key(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "RotateMe", "api")
        key_id = entry["id"]

        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "rotate", key_id]
        )
        assert result.exit_code == 0
        assert "Rotated" in result.output or "v2" in result.output or "New" in result.output

    def test_revoke_key(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "RevokeMe", "api")
        key_id = entry["id"]

        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "revoke", key_id]
        )
        assert result.exit_code == 0
        assert "Revoked" in result.output

    def test_verify_valid(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "VerifyMe", "api")
        api_key = entry["api_key"]

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "verify", api_key])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_invalid(self, runner, tmp_keystore):
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "verify", "ak_fake123"])
        assert result.exit_code == 0
        assert "INVALID" in result.output

    def test_verify_json_output(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "JsonVerify", "api")
        api_key = entry["api_key"]

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "verify", "--json-output", api_key])
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert data["status"] == "valid"

    def test_import_key(self, runner, tmp_keystore):
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "import", "ak_myimportedkey123",
             "--name", "Imported", "--service", "api"]
        )
        assert result.exit_code == 0
        assert "Imported" in result.output

    def test_import_key_stores_hash(self, runner, tmp_keystore):
        api_key = "ak_testimportkey123abc"
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "import", api_key,
             "--name", "HashTest", "--service", "api"]
        )
        assert result.exit_code == 0

        # Reload keystore from disk to get CLI-written data
        ks_fresh = Keystore(tmp_keystore.key_dir)
        v = verify_api_key(ks_fresh, api_key)
        assert v is not None
        assert v["status"] == "valid"

    def test_export_env(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "ExportKey", "api-gateway")
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "export", "--format", "env"]
        )
        assert result.exit_code == 0
        assert "export" in result.output

    def test_export_dotenv(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "DotenvKey", "api")
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "export", "--format", "dotenv"]
        )
        assert result.exit_code == 0
        assert "export" not in result.output  # dotenv has no export prefix
        assert "DOTENVKEY" in result.output

    def test_export_github_actions(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "GHKey", "api")
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "export", "--format", "github-actions"]
        )
        assert result.exit_code == 0
        assert "GITHUB_ENV" in result.output

    def test_export_json(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "JsonExport", "api")
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "export", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        assert isinstance(data, list)

    def test_audit_all_healthy(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "Healthy", "api")
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "audit"])
        assert result.exit_code == 0
        assert "healthy" in result.output.lower()

    def test_audit_with_expired(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "Expired", "api")
        e = tmp_keystore.get(entry["id"])
        e["expires_at"] = "2020-01-01T00:00:00Z"
        tmp_keystore.put(entry["id"], e)

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "audit"])
        assert result.exit_code == 0
        assert "EXPIRED" in result.output

    def test_audit_with_revoked(self, runner, tmp_keystore):
        entry = create_api_key_entry(tmp_keystore, "Revoked", "api")
        e = tmp_keystore.get(entry["id"])
        e["revoked"] = True
        tmp_keystore.put(entry["id"], e)

        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "audit"])
        assert result.exit_code == 0
        assert "REVOKED" in result.output

    def test_stats(self, runner, tmp_keystore):
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "stats"])
        assert result.exit_code == 0
        assert "Total keys" in result.output
