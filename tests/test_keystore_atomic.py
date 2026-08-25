"""Atomic keystore persistence + master key validation."""
import os

import pytest

from apiauth.keystore import Keystore, _get_or_create_master_key


def _make_keystore(tmp_path):
    return Keystore(key_dir=tmp_path)


def test_save_is_atomic_and_reloadable(tmp_path):
    ks = _make_keystore(tmp_path)
    ks.put("k1", {"type": "api_key", "name": "n", "service": "s"})
    # No temp files left behind after a successful save.
    leftovers = [p for p in os.listdir(tmp_path) if p.startswith(".keys-")]
    assert leftovers == []
    # A fresh instance reads back exactly what was written.
    ks2 = Keystore(key_dir=tmp_path)
    assert ks2.get("k1")["name"] == "n"


def test_torn_store_does_not_silently_overwrite_entries(tmp_path):
    """Simulate a torn write: garbage in keys.json must raise, never reset."""
    ks = _make_keystore(tmp_path)
    ks.put("k1", {"type": "api_key", "name": "n"})
    store = tmp_path / "keys.json"
    store.write_bytes(b"\x00" * 64)
    with pytest.raises(RuntimeError, match="Failed to decrypt"):
        Keystore(key_dir=tmp_path)
    # The corrupt file was NOT replaced by an empty store.
    assert store.stat().st_size == 64


def test_corrupt_master_key_fails_loudly(tmp_path):
    ks = _make_keystore(tmp_path)
    ks.put("k1", {"type": "api_key", "name": "n"})
    (tmp_path / "master.key").write_bytes(b"short")
    with pytest.raises(RuntimeError, match="corrupt: expected 32 bytes"):
        _get_or_create_master_key(tmp_path)
    # ...and the bad key was not silently regenerated over.
    assert (tmp_path / "master.key").read_bytes() == b"short"
