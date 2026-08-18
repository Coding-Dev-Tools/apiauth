"""Test that the verify command's help text and output accurately describe JWT verification.

Regression test for docs-honesty bug: the verify command claimed "signature is not
re-verified" when in fact verify_jwt_token() DOES verify the HMAC signature against
the stored signing_secret. Misleading users about security posture is a vulnerability.
"""

from __future__ import annotations

import pytest
from apiauth.cli import cli
from apiauth.keygen import create_jwt_entry
from apiauth.keystore import Keystore
from click.testing import CliRunner


@pytest.fixture
def tmp_keystore(tmp_path):
    return Keystore(key_dir=tmp_path)


def test_verify_help_does_not_claim_signature_unverified():
    """The verify command help text must not claim signature is unverified."""
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--help"])
    assert result.exit_code == 0
    combined = result.output or ""
    # Must NOT contain the old misleading text
    assert "signature is not re-verified" not in combined.lower(), (
        "verify --help still claims signature is not re-verified; "
        "this contradicts keygen.verify_jwt_token which verifies HMAC-SHA256"
    )
    assert "jti lookup only" not in combined.lower(), (
        "verify --help still claims JTI-only lookup; signature IS verified"
    )


def test_verify_valid_jwt_output_does_not_claim_signature_unverified(tmp_keystore):
    """When verifying a valid JWT, output must not say signature is unverified."""
    runner = CliRunner()
    entry = create_jwt_entry(
        keystore=tmp_keystore,
        name="docs-test",
        service="test",
        expiry_days=30,
    )
    token = entry["token"]
    result = runner.invoke(cli, ["-d", str(tmp_keystore.key_dir), "verify", token])
    combined = ((result.output or "") + (getattr(result, "stderr", "") or "")).lower()
    assert "signature not re-verified" not in combined, (
        "verify output still claims signature not re-verified for valid JWT"
    )
    assert "jti only" not in combined, "verify output still claims JTI-only for valid JWT"
