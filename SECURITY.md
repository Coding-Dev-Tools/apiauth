# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

We release patches for security vulnerabilities in the latest version.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's private vulnerability reporting feature:

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Fill in the details

We aim to respond within 48 hours and will keep you updated on the fix.

## Security Best Practices

- Keep your dependencies up to date
- Use `pip audit` to check for known vulnerabilities
- Report any security concerns promptly

## Security Architecture

APIAuth uses several security controls:

- **Encryption**: AES-256-GCM for keystore encryption
- **Key Derivation**: PBKDF2 with 100,000 iterations for master key derivation
- **Storage**: Only SHA-256 hashes of API keys and JWT signing secrets are stored
- **Key Rotation**: Previous key values are hashed out on rotation
- **Verification**: Constant-time hash comparison for API key verification
- **Offline Operation**: No telemetry, no network calls, fully air-gapped capable

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Keystore theft | AES-256-GCM encryption with PBKDF2-derived key |
| Key exposure on rotation | Previous values hashed with SHA-256 before rotation |
| Timing attacks | Constant-time comparison for hash verification |
| Replay attacks | JTI-based JWT tracking with revocation support |
| Supply chain | Dependabot weekly updates, pinned GitHub Actions SHAs |

## Compliance

- No PII stored in keystore
- GDPR-compliant by design (no personal data collection)
- SOC 2 compatible audit trail via `apiauth audit` command
