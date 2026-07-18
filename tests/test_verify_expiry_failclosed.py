"""Regression tests: expiry verification must FAIL CLOSED.

A key or JWT whose stored ``expires_at`` is naive (no offset) or otherwise
unparseable previously slipped through the ``except: pass`` in
``verify_api_key`` / ``verify_jwt_token`` and was reported as ``"valid"`` --
a silent fail-open in a security library. These tests lock in the corrected
behavior: naive timestamps are compared correctly, and an unparseable expiry
yields ``status == "invalid"`` (never ``"valid"``).
"""

from __future__ import annotations

import pytest
import tempfile
from apiauth.keygen import (
    create_api_key_entry,
    create_jwt_entry,
    verify_api_key,
    verify_jwt_token,
)
from apiauth.keystore import Keystore


@pytest.fixture
def tmp_keystore():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Keystore(tmpdir)


def _set_expiry(ks, key_id, value):
    entry = ks.get(key_id)
    entry["expires_at"] = value
    ks.put(key_id, entry)


class TestApiKeyExpiryFailClosed:
    def test_naive_past_expiry_is_expired_not_valid(self, tmp_keystore):
        r = create_api_key_entry(tmp_keystore, "NaivePast", "api")
        _set_expiry(tmp_keystore, r["id"], "2020-01-01T00:00:00")  # naive, past
        v = verify_api_key(tmp_keystore, r["api_key"])
        assert v is not None
        assert v["status"] == "expired"  # previously silently "valid"

    def test_naive_future_expiry_is_valid(self, tmp_keystore):
        r = create_api_key_entry(tmp_keystore, "NaiveFuture", "api")
        _set_expiry(tmp_keystore, r["id"], "2099-01-01T00:00:00")  # naive, future
        v = verify_api_key(tmp_keystore, r["api_key"])
        assert v is not None
        assert v["status"] == "valid"

    def test_malformed_expiry_fails_closed(self, tmp_keystore):
        r = create_api_key_entry(tmp_keystore, "Malformed", "api")
        _set_expiry(tmp_keystore, r["id"], "not-a-real-date")
        v = verify_api_key(tmp_keystore, r["api_key"])
        assert v is not None
        assert v["status"] == "invalid"  # must NOT be "valid"

    def test_non_string_expiry_fails_closed(self, tmp_keystore):
        r = create_api_key_entry(tmp_keystore, "NonString", "api")
        _set_expiry(tmp_keystore, r["id"], 1234567890)  # e.g. epoch int
        v = verify_api_key(tmp_keystore, r["api_key"])
        assert v is not None
        assert v["status"] == "invalid"

    def test_valid_zulu_expiry_still_valid(self, tmp_keystore):
        r = create_api_key_entry(tmp_keystore, "Zulu", "api")
        _set_expiry(tmp_keystore, r["id"], "2099-01-01T00:00:00Z")
        v = verify_api_key(tmp_keystore, r["api_key"])
        assert v["status"] == "valid"


class TestJwtExpiryFailClosed:
    def test_naive_past_expiry_is_expired(self, tmp_keystore):
        r = create_jwt_entry(tmp_keystore, "JwtNaivePast", "auth")
        _set_expiry(tmp_keystore, r["id"], "2020-01-01T00:00:00")
        v = verify_jwt_token(tmp_keystore, r["token"])
        assert v is not None
        assert v["status"] == "expired"

    def test_malformed_expiry_fails_closed(self, tmp_keystore):
        r = create_jwt_entry(tmp_keystore, "JwtMalformed", "auth")
        _set_expiry(tmp_keystore, r["id"], "garbage")
        v = verify_jwt_token(tmp_keystore, r["token"])
        assert v is not None
        assert v["status"] == "invalid"
