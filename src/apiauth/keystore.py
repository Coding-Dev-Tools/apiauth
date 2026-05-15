"""Encrypted local keystore for API keys using AES-256-GCM."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_DEFAULT_KEY_DIR = Path.home() / ".apiauth"
_KEY_FILE = "master.key"
_STORE_FILE = "keys.json"
_NONCE_BYTES = 12


def _get_or_create_master_key(key_dir: Path) -> bytes:
    """Load existing master key or generate a new one."""
    key_path = key_dir / _KEY_FILE
    if key_path.exists():
        return key_path.read_bytes()

    key_dir.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    key_path.write_bytes(key)
    os.chmod(str(key_path), 0o600)  # Restrict permissions
    return key


class Keystore:
    """AES-256-GCM encrypted local keystore for API keys and JWTs."""

    def __init__(self, key_dir: str | Path | None = None) -> None:
        self.key_dir = Path(key_dir or _DEFAULT_KEY_DIR)
        self._master_key = _get_or_create_master_key(self.key_dir)
        self._aesgcm = AESGCM(self._master_key)
        self._store_path = self.key_dir / _STORE_FILE
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._store_path.exists():
            self._entries = {}
            return

        raw = self._store_path.read_bytes()
        if not raw:
            self._entries = {}
            return

        try:
            nonce = raw[:12]
            ciphertext = raw[12:]
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            self._entries = json.loads(plaintext.decode("utf-8"))
        except Exception:
            self._entries = {}

    def _save(self) -> None:
        plaintext = json.dumps(self._entries, indent=2, default=str).encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        self._store_path.write_bytes(nonce + ciphertext)
        os.chmod(str(self._store_path), 0o600)

    def get_all(self) -> dict[str, dict[str, Any]]:
        """Return all stored entries."""
        return dict(self._entries)

    def get(self, key_id: str) -> dict[str, Any] | None:
        """Get a single entry by its key ID."""
        return self._entries.get(key_id)

    def put(self, key_id: str, entry: dict[str, Any]) -> None:
        """Store or update an entry."""
        self._entries[key_id] = entry
        self._save()

    def delete(self, key_id: str) -> bool:
        """Delete an entry. Returns True if it existed."""
        existed = key_id in self._entries
        if existed:
            del self._entries[key_id]
            self._save()
        return existed

    def list_keys(self, service: str | None = None) -> list[dict[str, Any]]:
        """List all entries, optionally filtered by service."""
        results = []
        for kid, entry in self._entries.items():
            if service and entry.get("service", "") != service:
                continue
            results.append({"id": kid, **entry})
        return sorted(results, key=lambda e: e.get("created_at", ""))

    def get_stats(self) -> dict[str, Any]:
        """Get storage statistics."""
        total = len(self._entries)
        by_service: dict[str, int] = {}
        for entry in self._entries.values():
            s = entry.get("service", "unknown")
            by_service[s] = by_service.get(s, 0) + 1
        return {
            "total_keys": total,
            "by_service": by_service,
            "store_path": str(self._store_path),
            "key_path": str(self.key_dir / _KEY_FILE),
        }
