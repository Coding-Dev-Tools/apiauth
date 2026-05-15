"""API key and JWT generation utilities."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import uuid

UTC = datetime.timezone.utc

from .keystore import Keystore


def generate_api_key(prefix: str = "ak", byte_length: int = 32) -> str:
    """Generate a cryptographically secure API key.

    Format: {prefix}_{base64url(32 bytes)}
    """
    raw = secrets.token_bytes(byte_length)
    token = _base64url_no_pad(raw)
    return f"{prefix}_{token}"


def _base64url_no_pad(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _generate_key_id() -> str:
    return uuid.uuid4().hex[:12]


def _timestamp() -> str:
    return datetime.datetime.now(UTC).isoformat()[:23] + "Z"


def create_api_key_entry(
    keystore: Keystore,
    name: str,
    service: str,
    expiry_days: int | None = None,
    rate_limit: int | None = None,
    prefix: str = "ak",
) -> dict:
    """Generate a new API key and store it in the keystore."""
    key_id = _generate_key_id()
    api_key = generate_api_key(prefix=prefix)

    # Hash the key for storage (we store the hash, not the plaintext key value)
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    now = _timestamp()
    expiry = None
    if expiry_days:
        expiry = (
            datetime.datetime.now(UTC) + datetime.timedelta(days=expiry_days)
        ).isoformat()[:23] + "Z"

    entry = {
        "type": "api_key",
        "name": name,
        "service": service,
        "key_hash": key_hash,
        "prefix": api_key[:20],  # Store prefix for identification
        "created_at": now,
        "last_used": None,
        "expires_at": expiry,
        "rate_limit": rate_limit,
        "revoked": False,
        "version": 1,
    }

    keystore.put(key_id, entry)

    return {
        "id": key_id,
        "api_key": api_key,  # Return plaintext only on creation
        **entry,
    }


def create_jwt_entry(
    keystore: Keystore,
    name: str,
    service: str,
    expiry_days: int = 30,
    claims: dict | None = None,
) -> dict:
    """Generate a JWT and store its metadata in the keystore."""
    key_id = _generate_key_id()

    # Generate a signing secret
    signing_secret = secrets.token_hex(32)

    now = datetime.datetime.now(UTC)
    payload = {
        "iss": "apiauth",
        "sub": f"service:{service}:{name}",
        "iat": now,
        "jti": key_id,
    }
    if expiry_days:
        payload["exp"] = now + datetime.timedelta(days=expiry_days)
    if claims:
        payload.update(claims)

    # Create the JWT
    import jwt as pyjwt
    token = pyjwt.encode(payload, signing_secret, algorithm="HS256")

    now = _timestamp()
    expiry = None
    if expiry_days:
        expiry = (
            datetime.datetime.now(UTC) + datetime.timedelta(days=expiry_days)
        ).isoformat()[:23] + "Z"

    entry = {
        "type": "jwt",
        "name": name,
        "service": service,
        "signing_secret_hash": hashlib.sha256(signing_secret.encode()).hexdigest(),
        "created_at": now,
        "last_used": None,
        "expires_at": expiry,
        "revoked": False,
        "version": 1,
        "claims": payload,
    }

    keystore.put(key_id, entry)

    return {
        "id": key_id,
        "token": token,  # Return plaintext only on creation
        **entry,
    }


def rotate_key(
    keystore: Keystore,
    key_id: str,
    expiry_days: int | None = None,
) -> dict | None:
    """Rotate an existing key: generate new value, increment version."""
    entry = keystore.get(key_id)
    if entry is None:
        return None

    new_api_key = generate_api_key()
    new_hash = hashlib.sha256(new_api_key.encode()).hexdigest()

    now = _timestamp()
    expiry = None
    if expiry_days:
        expiry = (
            datetime.datetime.now(UTC) + datetime.timedelta(days=expiry_days)
        ).isoformat()[:23] + "Z"

    updated = dict(entry)
    updated["previous_hash"] = entry.get("key_hash")
    updated["key_hash"] = new_hash
    updated["prefix"] = new_api_key[:20]
    updated["version"] = entry.get("version", 1) + 1
    updated["rotated_at"] = now
    updated["expires_at"] = expiry or entry.get("expires_at")
    updated["revoked"] = False

    keystore.put(key_id, updated)

    return {
        "id": key_id,
        "api_key": new_api_key,
        **updated,
    }


def verify_api_key(keystore: Keystore, api_key: str) -> dict | None:
    """Verify a plaintext API key against the keystore.

    Returns the entry metadata if the key hash matches and key is not revoked.
    """
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    for kid, entry in keystore.get_all().items():
        if entry.get("type") != "api_key":
            continue
        if entry.get("key_hash") == key_hash:
            if entry.get("revoked"):
                return {"id": kid, "status": "revoked", **entry}
            # Check expiry
            if entry.get("expires_at"):
                from datetime import datetime
                try:
                    exp = datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
                    if datetime.now(UTC) > exp:
                        return {"id": kid, "status": "expired", **entry}
                except (ValueError, TypeError):
                    pass
            return {"id": kid, "status": "valid", **entry}
    return None


def verify_jwt_token(keystore: Keystore, token: str) -> dict | None:
    """Verify a JWT token by decoding it and matching the jti to the keystore.

    Returns entry metadata if the JWT jti matches and key is not revoked.
    """
    import jwt as pyjwt

    try:
        # Decode without verification first to get the jti
        unverified = pyjwt.decode(token, options={"verify_signature": False, "verify_exp": False})
        jti = unverified.get("jti")
    except Exception:
        return None

    if not jti:
        return None

    entry = keystore.get(jti)
    if not entry or entry.get("type") != "jwt":
        return None

    if entry.get("revoked"):
        return {"id": jti, "status": "revoked", **entry}

    # Check expiry
    if entry.get("expires_at"):
        from datetime import datetime
        try:
            exp = datetime.fromisoformat(entry["expires_at"].replace("Z", "+00:00"))
            if datetime.now(UTC) > exp:
                return {"id": jti, "status": "expired", **entry}
        except (ValueError, TypeError):
            pass

    return {"id": jti, "status": "valid", **entry}


def rotate_jwt(
    keystore: Keystore,
    key_id: str,
    expiry_days: int = 30,
) -> dict | None:
    """Rotate a JWT: generate new token, increment version."""
    entry = keystore.get(key_id)
    if entry is None:
        return None

    signing_secret = secrets.token_hex(32)
    import jwt as pyjwt

    now_dt = datetime.datetime.now(UTC)
    payload = dict(entry.get("claims", {}))
    payload["iat"] = now_dt
    payload["jti"] = key_id
    if expiry_days:
        payload["exp"] = now_dt + datetime.timedelta(days=expiry_days)

    token = pyjwt.encode(payload, signing_secret, algorithm="HS256")

    now = _timestamp()
    expiry = None
    if expiry_days:
        expiry = (
            datetime.datetime.now(UTC) + datetime.timedelta(days=expiry_days)
        ).isoformat()[:23] + "Z"

    updated = dict(entry)
    updated["previous_hash"] = entry.get("signing_secret_hash")
    updated["signing_secret_hash"] = hashlib.sha256(signing_secret.encode()).hexdigest()
    updated["version"] = entry.get("version", 1) + 1
    updated["rotated_at"] = now
    updated["expires_at"] = expiry
    updated["revoked"] = False
    updated["claims"] = payload

    keystore.put(key_id, updated)

    return {
        "id": key_id,
        "token": token,
        **updated,
    }
