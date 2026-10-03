"""rotate_key()/rotate_jwt() must refuse to operate on mismatched entry types.

Running the API-key rotation path over a JWT entry (or vice versa) used to
silently corrupt the keystore entry: key_hash/prefix were overwritten,
signing_secret_hash left stale, version bumped. These guards make the
mismatch loud instead of silent.
"""
import pytest
from apiauth.keygen import create_api_key_entry, create_jwt_entry, rotate_jwt, rotate_key
from apiauth.keystore import Keystore


def test_rotate_key_on_jwt_raises(tmp_path):
    tmp_keystore = Keystore(str(tmp_path / "ks"))
    created = create_jwt_entry(tmp_keystore, name="svc", service="api")
    with pytest.raises(ValueError, match="rotate_key"):
        rotate_key(tmp_keystore, created["id"])
    # Entry is untouched.
    assert tmp_keystore.get(created["id"])["type"] == "jwt"
    assert "key_hash" not in tmp_keystore.get(created["id"])


def test_rotate_jwt_on_api_key_raises(tmp_path):
    tmp_keystore = Keystore(str(tmp_path / "ks"))
    created = create_api_key_entry(tmp_keystore, name="k", service="api")
    orig = dict(tmp_keystore.get(created["id"]))
    with pytest.raises(ValueError, match="rotate_jwt"):
        rotate_jwt(tmp_keystore, created["id"])
    assert tmp_keystore.get(created["id"]) == orig


def test_correct_type_rotation_still_works(tmp_path):
    tmp_keystore = Keystore(str(tmp_path / "ks"))
    key_entry = create_api_key_entry(tmp_keystore, name="k", service="api")
    rotated = rotate_key(tmp_keystore, key_entry["id"])
    assert rotated["version"] == 2
    jwt_entry = create_jwt_entry(tmp_keystore, name="j", service="api")
    rotated_jwt = rotate_jwt(tmp_keystore, jwt_entry["id"])
    assert rotated_jwt["version"] == 2
