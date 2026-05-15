"""Verify API keys and JWTs against the keystore."""

from __future__ import annotations

import datetime

UTC = datetime.timezone.utc

# Re-export verify functions from keygen for backward compatibility
from .keygen import verify_api_key, verify_jwt_token  # noqa: F401


def check_expiry(entry: dict) -> str | None:
    """Check if a key entry is expired or expiring soon.

    Returns:
      'expired' -- already expired
      'expiring' -- expires within 7 days
      None -- no expiry or not expired
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
