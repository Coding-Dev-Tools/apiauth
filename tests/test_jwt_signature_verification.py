"""Test that verify_jwt_token actually verifies the JWT signature.

Regression test for a critical security vulnerability where verify_jwt_token
decoded the JWT without verifying the signature, allowing an attacker who knows
a valid jti to forge arbitrary tokens.
"""

from __future__ import annotations

import jwt as pyjwt
import pytest
from apiauth.keygen import create_jwt_entry, verify_jwt_token
from apiauth.keystore import Keystore


@pytest.fixture
def tmp_keystore(tmp_path):
    """Create a keystore in a temporary directory."""
    return Keystore(key_dir=tmp_path)


def test_verify_jwt_rejects_forged_signature(tmp_keystore):
    """A JWT with a valid jti but wrong signing secret must be rejected.

    This is the core security property: knowing the jti alone must not
    be sufficient to pass verification. The signature must match the
    stored signing_secret_hash.
    """
    # Create a legitimate JWT entry
    result = create_jwt_entry(
        keystore=tmp_keystore,
        name="test-service",
        service="test",
        expiry_days=30,
    )
    key_id = result["id"]

    # Forge a token with the correct jti but a different signing secret
    forged_payload = {
        "iss": "apiauth",
        "sub": "service:test:test-service",
        "jti": key_id,
        "iat": result["claims"]["iat"],
        "exp": result["claims"]["exp"],
    }
    forged_token = pyjwt.encode(forged_payload, "wrong-secret", algorithm="HS256")

    # The forged token must NOT verify as valid
    v = verify_jwt_token(tmp_keystore, forged_token)
    assert v is not None, "Should find the entry by jti"
    assert v["status"] != "valid", (
        f"Forged JWT with wrong signature was accepted as valid! "
        f"Got status={v['status']}. This is a critical security vulnerability."
    )


def test_verify_jwt_accepts_legitimate_token(tmp_keystore):
    """A legitimately created JWT must still verify successfully."""
    result = create_jwt_entry(
        keystore=tmp_keystore,
        name="legit-service",
        service="legit",
        expiry_days=30,
    )

    v = verify_jwt_token(tmp_keystore, result["token"])
    assert v is not None
    assert v["status"] == "valid"


def test_verify_jwt_rejects_tampered_claims(tmp_keystore):
    """A JWT with tampered claims (even with same jti) must be rejected."""
    result = create_jwt_entry(
        keystore=tmp_keystore,
        name="tamper-test",
        service="tamper",
        expiry_days=30,
    )

    # Decode the legitimate token to get its structure
    decoded = pyjwt.decode(
        result["token"], options={"verify_signature": False}
    )

    # Tamper with the subject claim
    decoded["sub"] = "service:admin:elevated-privilege"

    # Re-encode with the wrong secret (attacker doesn't know the real one)
    tampered_token = pyjwt.encode(decoded, "attacker-secret", algorithm="HS256")

    v = verify_jwt_token(tmp_keystore, tampered_token)
    assert v is not None
    assert v["status"] != "valid", (
        "Tampered JWT was accepted as valid — signature verification missing"
    )
