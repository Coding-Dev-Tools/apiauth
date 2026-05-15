# APIAuth

**CLI tool for API key and JWT lifecycle management — generate, store, verify, rotate, and revoke keys with an encrypted local keystore.**

[![CI](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml/badge.svg)](https://github.com/Coding-Dev-Tools/apiauth/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/Coding-Dev-Tools/apiauth/blob/main/LICENSE)

**Why APIAuth?** API keys proliferate in every codebase — staging keys, prod keys, third-party service keys, JWT secrets for auth. Most teams store them in `.env` files, spreadsheets, or chat history. When a key is compromised, tracking down everywhere it was used and rotating it is a manual nightmare. APIAuth gives you a single encrypted keystore with full lifecycle management: generate, import, list, verify, rotate, revoke, and export — all from your terminal.

## Quick Start

```bash
pip install apiauth

# Generate an API key
apiauth generate api-key --name "My API Key" --service "api-gateway" --expiry-days 90

# List all keys with expiry status
apiauth list

# Export for CI/CD
apiauth export --format github-actions
```

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

## Commands

### `apiauth generate`

Generate a new API key or JWT.

```bash
apiauth generate api-key --name "My API Key" --service "api-gateway" --expiry-days 90
apiauth generate jwt --name "My JWT" --service "auth-service" --expiry-days 30 --claim role=admin
```

### `apiauth list`

List all stored keys with expiry status.

```bash
apiauth list
apiauth list --service "api-gateway"
apiauth list --json-output
```

### `apiauth show`

Show details for a specific key.

```bash
apiauth show <key-id>
```

### `apiauth verify`

Verify an API key against stored hashes.

```bash
apiauth verify ak_xYz123abc...
```

### `apiauth import`

Import an existing key into the keystore.

```bash
apiauth import ak_existing_key_value --name "Legacy Key" --service "api"
```

### `apiauth rotate`

Rotate a key and hash out the previous value.

```bash
apiauth rotate <key-id>
```

### `apiauth revoke`

Revoke a key instantly.

```bash
apiauth revoke <key-id>
```

### `apiauth export`

Export keys for external consumption.

```bash
apiauth export --format env --service "api-gateway"
apiauth export --format dotenv
apiauth export --format github-actions
apiauth export --format json
```

### `apiauth audit`

Audit keystore health.

```bash
apiauth audit
```

### `apiauth stats`

View keystore statistics.

```bash
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

## Pricing

APIAuth is one of eight tools in the Revenue Holdings suite. One license covers all CLI tools.

| Plan | Price | Best For |
|------|-------|----------|
| **Free** | $0 | Individual devs, OSS — CLI only, 5 keys |
| **APIAuth Individual** | **$12/mo** ($10 billed annually) | Professional devs — unlimited keys, all export formats |
| **Suite (all 8 tools)** | **$49/mo** ($39 billed annually) | Full Revenue Holdings toolkit — 40% savings |
| **Team** | **$79/mo** ($63 billed annually) | Up to 5 devs — shared keystore, team dashboard, alerts |
| **Enterprise** | Custom | SSO, RBAC, compliance reports, dedicated support |

🔹 **No lock-in**: CLI works fully offline on the free tier — no telemetry, no phone-home.
🔹 **Annual billing**: Save 20%.

### Per-Tier Features

| Feature | Free | Individual | Suite | Team | Enterprise |
|---------|:----:|:----------:|:-----:|:----:|:----------:|
| CLI: generate, verify, export | ✓ | ✓ | ✓ | ✓ | ✓ |
| Unlimited keys | 5 keys | ✓ | ✓ | ✓ | ✓ |
| All export formats | `env` only | ✓ | ✓ | ✓ | ✓ |
| JWT with custom claims | — | ✓ | ✓ | ✓ | ✓ |
| Audit & stats | — | ✓ | ✓ | ✓ | ✓ |
| Shared team keystore | — | — | — | ✓ | ✓ |
| Dashboard & analytics | — | — | — | ✓ | ✓ |
| Compliance reports | — | — | — | — | ✓ |
| RBAC / SSO / SAML / OIDC | — | — | — | — | ✓ |
| Priority support | Community | 24h | 24h | 8h | Dedicated |

---

<p align="center">
  <sub>Part of <a href="https://coding-dev-tools.github.io/revenueholdings.dev/">Revenue Holdings</a> — CLI tools built by autonomous AI.</sub>
</p>

## Storage

Keys and configuration are stored in `~/.apiauth/`:
- `~/.apiauth/master.key` — AES-256-GCM master key (never shared)
- `~/.apiauth/keystore.enc` — encrypted key-value store
- `~/.apiauth/config.yaml` — user configuration

## CI/CD Integration

```bash
# In your deployment pipeline
export $(apiauth export --format env --service production)

# Audit before release
apiauth audit --exit-on-expired
```

## Roadmap

- [ ] Vault-backed remote keystore (HashiCorp Vault, AWS Secrets Manager)
- [ ] Auto-expiry notifications via CLI or webhook
- [ ] GPG key support
- [ ] MCP server for AI-assisted key management
- [ ] Web UI for team keystore management
- [ ] Terraform provider for secret provisioning

## License

MIT — see [LICENSE](LICENSE)

---

<sub>Part of [Revenue Holdings](https://coding-dev-tools.github.io/revenueholdings.dev/) — a suite of 10 developer CLI tools built by autonomous AI agents. Also check out [API Contract Guardian](https://github.com/Coding-Dev-Tools/api-contract-guardian) (breaking change detection), [DeployDiff](https://github.com/Coding-Dev-Tools/deploydiff) (infrastructure diffs), [json2sql](https://github.com/Coding-Dev-Tools/json2sql) (JSON → SQL), [ConfigDrift](https://github.com/Coding-Dev-Tools/configdrift) (config drift detection), [DeadCode](https://github.com/Coding-Dev-Tools/deadcode) (dead code cleanup), [APIGhost](https://github.com/Coding-Dev-Tools/apighost) (mock API server), [Envault](https://github.com/Coding-Dev-Tools/envault) (env sync), [SchemaForge](https://github.com/Coding-Dev-Tools/schemaforge) (ORM converter), and [click-to-mcp](https://github.com/Coding-Dev-Tools/click-to-mcp) (CLI → MCP server).</sub>
