"""Test atomic write behavior for keystore."""

import os
from apiauth.keystore import Keystore
from pathlib import Path


def test_keystore_atomic_write_no_temp_files(tmp_path: Path) -> None:
    """Verify that keystore save leaves no temporary files behind."""
    key_dir = tmp_path / "keystore"
    key_dir.mkdir()

    ks = Keystore(key_dir=key_dir)
    ks.put("test-key", {"id": "test-key", "type": "api_key", "value": "test123"})

    # Check no temp files remain
    files = list(key_dir.iterdir())
    filenames = [f.name for f in files]

    # Should only have master.key and keys.json
    assert "master.key" in filenames
    assert "keys.json" in filenames
    assert len(filenames) == 2, f"Unexpected files left behind: {filenames}"


def test_keystore_atomic_write_preserves_data(tmp_path: Path) -> None:
    """Verify that atomic write preserves valid data."""
    key_dir = tmp_path / "keystore"
    key_dir.mkdir()

    # Write initial data
    ks1 = Keystore(key_dir=key_dir)
    ks1.put("key1", {"id": "key1", "type": "api_key", "value": "value1"})
    ks1.put("key2", {"id": "key2", "type": "jwt", "value": "value2"})

    # Reload and verify
    ks2 = Keystore(key_dir=key_dir)
    entries = ks2.get_all()

    assert len(entries) == 2
    assert "key1" in entries
    assert "key2" in entries
    assert entries["key1"]["value"] == "value1"
    assert entries["key2"]["value"] == "value2"


def test_keystore_atomic_write_file_permissions(tmp_path: Path) -> None:
    """Verify that atomic write maintains restrictive permissions."""
    key_dir = tmp_path / "keystore"
    key_dir.mkdir()

    ks = Keystore(key_dir=key_dir)
    ks.put("test-key", {"id": "test-key", "type": "api_key", "value": "test"})

    store_path = key_dir / "keys.json"
    key_path = key_dir / "master.key"

    # Check permissions (on Unix-like systems)
    if os.name != "nt":  # Skip on Windows
        store_mode = store_path.stat().st_mode & 0o777
        key_mode = key_path.stat().st_mode & 0o777

        assert store_mode == 0o600, f"keys.json permissions: {oct(store_mode)}"
        assert key_mode == 0o600, f"master.key permissions: {oct(key_mode)}"
