"""Tests for APIAuth CLI keystore and keygen modules."""

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
)
from apiauth.cli import cli


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


class TestCLIIntegration:
    """Test CLI commands via Click CliRunner."""

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "0.1.0" in result.output

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
        # Pre-populate
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

    def test_export_env(self, runner, tmp_keystore):
        create_api_key_entry(tmp_keystore, "ExportKey", "api-gateway")
        result = runner.invoke(
            cli, ["--key-dir", str(tmp_keystore.key_dir), "export", "--format", "env"]
        )
        assert result.exit_code == 0
        assert "EXPORTKEY" in result.output or "ExportKey" in result.output

    def test_stats(self, runner, tmp_keystore):
        result = runner.invoke(cli, ["--key-dir", str(tmp_keystore.key_dir), "stats"])
        assert result.exit_code == 0
        assert "Total keys" in result.output
