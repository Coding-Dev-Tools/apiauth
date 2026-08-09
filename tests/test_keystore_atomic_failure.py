"""Test that keystore survives write failures."""

import contextlib
from apiauth.keystore import Keystore
from pathlib import Path
from unittest.mock import patch


def test_keystore_survives_write_failure(tmp_path: Path) -> None:
    """If _save() fails mid-write, existing data must remain intact."""
    key_dir = tmp_path / "keystore"
    key_dir.mkdir()

    # Write initial data
    ks1 = Keystore(key_dir=key_dir)
    ks1.put("original-key", {"id": "original-key", "value": "original-value"})

    # Verify initial state
    store_path = key_dir / "keys.json"
    assert store_path.exists()
    original_size = store_path.stat().st_size

    # Try to add new data, but make the write fail
    ks2 = Keystore(key_dir=key_dir)

    # Mock write to raise an exception after opening file
    with patch("pathlib.Path.write_bytes") as mock_write:
        mock_write.side_effect = OSError("Disk full")

        # This should fail, but original data must survive
        with contextlib.suppress(OSError):
            ks2.put("new-key", {"id": "new-key", "value": "new-value"})

    # Reload and verify original data is intact
    ks3 = Keystore(key_dir=key_dir)
    entries = ks3.get_all()

    assert "original-key" in entries, "Original key was lost during failed write!"
    assert entries["original-key"]["value"] == "original-value"

    # File size should be unchanged (no partial write)
    current_size = store_path.stat().st_size
    assert current_size == original_size, f"File size changed: {original_size} -> {current_size}"
