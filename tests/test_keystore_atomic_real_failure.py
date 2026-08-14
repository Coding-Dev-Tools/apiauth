"""Test that keystore survives realistic write failures (file truncation)."""

import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from apiauth.keystore import Keystore


def test_keystore_survives_truncating_write_failure(tmp_path: Path) -> None:
    """If write_bytes truncates the file but fails to write content,
    the original data must still be recoverable.
    
    This tests the REAL failure mode: open('wb') truncates immediately,
    then write() fails (disk full). Without atomic write, data is lost.
    """
    key_dir = tmp_path / "keystore"
    key_dir.mkdir()

    # Write initial data
    ks1 = Keystore(key_dir=key_dir)
    ks1.put("original-key", {"id": "original-key", "value": "original-value"})

    store_path = key_dir / "keys.json"
    assert store_path.exists()
    original_content = store_path.read_bytes()

    # Simulate realistic failure: file gets truncated but write fails
    original_write_bytes = Path.write_bytes
    
    def truncating_write_bytes(self_path, data):
        if self_path == store_path:
            # Truncate the file (real 'wb' behavior) then fail
            with open(self_path, 'wb'):
                pass  # truncates to zero bytes
            raise OSError("Disk full after truncation")
        return original_write_bytes(self_path, data)

    ks2 = Keystore(key_dir=key_dir)
    try:
        with patch.object(Path, 'write_bytes', truncating_write_bytes):
            ks2.put("new-key", {"id": "new-key", "value": "new-value"})
    except OSError:
        pass  # Expected

    # After atomic write implementation, original data must survive
    # even though the target file was truncated
    ks3 = Keystore(key_dir=key_dir)
    entries = ks3.get_all()
    
    assert "original-key" in entries, (
        "Original key was lost! Implementation is not atomic. "
        "Use temp file + os.replace for crash-safe writes."
    )
    assert entries["original-key"]["value"] == "original-value"
