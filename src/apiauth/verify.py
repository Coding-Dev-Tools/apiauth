"""Verify API keys and JWTs against the keystore."""

from __future__ import annotations

import datetime
import hashlib

UTC = datetime.timezone.utc


def verify_api_key(keystore, api_key: str) -> dict:
    """Verify an API key against stored hashes.

    Returns a dict with:
      - valid: bool
      - key_id: str or None
      - revoked: bool or None
      - expired: bool or None
      - rate_limit: int or None
    """
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    prefix = api_key[:20]

    for kid, entry in keystore.get_all().items():
        if entry.get("type") != "api_key":
            continue
        if entry.get("key_hash") != key_hash:
            continue
        # Match found
        result = {
            "valid": True,
            "key_id": kid,
            "revoked": entry.get("revoked", False),
            "expired": False,
            "rate_limit": entry.get("rate_limit"),
            "name": entry.get("name"),
            "service": entry.get("service"),
            "version": entry.get("version", 1),
        }
        # Check expiry
        if entry.get("expires_at"):
            try:
                exp = datetime.datetime.fromisoformat(
                    entry["expires_at"].replace("Z", "+00:00")
                )
                if datetime.datetime.now(UTC) > exp:
                    result["expired"] = True
                    result["valid"] = False
            except (ValueError, TypeError):
                pass

        if result["revoked"]:
            result["valid"] = False

        return result

    return {"valid": False, "key_id": None, "revoked": None, "expired": None, "rate_limit": None}


def check_expiry(entry: dict) -> str | None:
    """Check if a key entry is expired or expiring soon.

    Returns:
      'expired' — already expired
      'expiring' — expires within 7 days
      None — no expiry or not expired
    """
    exp_str = entry.get("expires_at")
    if not exp_str:
        return None

    try:
        exp = datetime.datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None

    now = datetime.datetime.now(UTC)
    if now > exp:
        return "expired"
    if (exp - now).days <= 7:
        return "expiring"
    return None
