# APIAuth

CLI tool for API key and JWT lifecycle management with encrypted local store.

[![CI](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml/badge.svg)](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/apiauth)](https://pypi.org/project/apiauth/)

## Features

- **Generate** API keys and JWTs with a single command
- **Import** existing API keys into the encrypted keystore
- **Verify** API keys against stored hashes — check revocation and expiry
- **Rotate** keys and tokens safely — previous values are hashed out
- **Revoke** compromised keys instantly
- **List & search** keys by service with expiry status indicators
- **Export** as environment variables, dotenv, JSON, or GitHub Actions format
- **Audit** keystore for expired, expiring, and revoked keys
- **Encrypted local keystore** — AES-256-GCM, master key stored in `~/.apiauth/`
- **CI/CD integration** — export keys for GitHub Actions, GitLab CI, etc.

## Installation

```bash
pip install apiauth
```

## Quick Start

```bash
# Generate an API key
apiauth generate api-key --name "My API Key" --service "api-gateway" --expiry-days 90

# Generate a JWT
apiauth generate jwt --name "My JWT" --service "auth-service" --expiry-days 30 --claim role=admin

# List all keys (with expiry status)
apiauth list
apiauth list --service "api-gateway"
apiauth list --json-output

# Show key details
apiauth show <key-id>

# Verify an API key
apiauth verify ak_xYz123abc...

# Import an existing key
apiauth import ak_existing_key_value --name "Legacy Key" --service "api"

# Rotate a key
apiauth rotate <key-id>

# Revoke a key
apiauth revoke <key-id>

# Export for CI/CD
apiauth export --format env --service "api-gateway"
apiauth export --format dotenv
apiauth export --format github-actions
apiauth export --format json

# Audit keystore health
apiauth audit

# View keystore stats
apiauth stats
```

## Export Formats

| Format | Use Case |
|--------|----------|
| `env` | Shell source scripts (`export KEY=value`) |
| `dotenv` | `.env` files (no `export` prefix) |
| `github-actions` | `$GITHUB_ENV` and workflow YAML |
| `json` | Programmatic consumption |

## Security

- Master key never leaves `~/.apiauth/master.key`
- Key store is encrypted with AES-256-GCM
- Plaintext keys are only displayed once on creation
- Rotated keys have their previous values hashed
- Imported keys are stored as SHA-256 hashes only
- `verify` command checks against stored hashes — no plaintext stored

## License

MIT
