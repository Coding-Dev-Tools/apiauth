# APIAuth

CLI tool for API key and JWT lifecycle management with encrypted local store.

[![CI](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml/badge.svg)](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/apiauth)](https://pypi.org/project/apiauth/)

## Features

- **Generate** API keys and JWTs with a single command
- **Rotate** keys and tokens safely — previous values are hashed out
- **Revoke** compromised keys instantly
- **List & search** keys by service
- **Export** as environment variables (for CI/CD integration)
- **Encrypted local keystore** — AES-256-GCM, master key stored in `~/.apiauth/`
- **CI/CD integration** — export keys for GitHub Actions, GitLab CI, etc.

## Installation

```bash
pip install apiauth
```

## Usage

### Generate an API key

```bash
apiauth generate api-key --name "My API Key" --service "api-gateway" --expiry-days 90
```

### Generate a JWT

```bash
apiauth generate jwt --name "My JWT" --service "auth-service" --expiry-days 30
```

### List all keys

```bash
apiauth list
apiauth list --service "api-gateway"
apiauth list --json-output
```

### Show key details

```bash
apiauth show <key-id>
```

### Rotate a key

```bash
apiauth rotate <key-id>
```

### Revoke a key

```bash
apiauth revoke <key-id>
```

### Export for CI/CD

```bash
apiauth export --format env --service "api-gateway"
```

### View keystore stats

```bash
apiauth stats
```

## Security

- Master key never leaves `~/.apiauth/master.key`
- Key store is encrypted with AES-256-GCM
- Plaintext keys are only displayed once on creation
- Rotated keys have their previous values hashed

## License

MIT
