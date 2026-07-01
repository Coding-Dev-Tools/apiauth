# APIAuth — Agent Instructions

## Quick Context

**APIAuth** — CLI tool for API key and JWT lifecycle management with encrypted local keystore (AES-256-GCM).  
**Subsidiary:** Coding-Dev-Tools | **Parent:** Revenue Holdings  
**North Star:** Generate revenue through CLI tools, SaaS products, and automated operations.  
**License:** MIT (optional `revenueholdings_license` package for enforcement)

---

## Repository Structure

```
apiauth/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml          # Multi-Python CI (3.10–3.13)
│   │   └── publish.yml     # PyPI publish on release
│   └── dependabot.yml      # Dependency updates
├── src/
│   └── apiauth/
│       ├── __init__.py     # __version__ = "0.2.0"
│       ├── cli.py          # Click CLI (500+ lines)
│       ├── keygen.py       # Key/JWT generation, rotation
│       ├── keystore.py     # AES-256-GCM encrypted keystore
│       └── verify.py       # Verification & expiry checks
├── tests/
│   └── test_cli.py         # 58 tests, all passing
├── pyproject.toml          # PEP 621, setuptools, ruff, pytest config
├── README.md               # Full CLI docs
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── SECURITY.md
└── .gitattributes
```

---

## Commands (Local Dev)

```bash
# Setup
python -m venv .venv && .venv/Scripts/activate  # Windows
pip install -e ".[dev]"

# Run tests (58 tests, ~1s)
pytest tests/ -v

# Lint
ruff check src/

# Full local CI simulation
pytest tests/ -v && ruff check src/

# Quick CLI smoke test
apiauth --version && apiauth generate api-key -n "Test" -s "test" && apiauth list
```

---

## CI/CD

| Workflow | Trigger | Matrix | Key Steps |
|----------|---------|--------|-----------|
| `ci.yml` | push/PR to master | Python 3.10–3.13 | checkout → setup-python → install deps → ruff → pytest → CLI smoke test |
| `publish.yml` | release published | Python 3.12 | checkout → build → twine check → PyPI publish (OIDC) |

**CI Status:** ✅ Passing (last check: 58 tests pass, ruff clean)

---

## Key Files to Know

| File | Purpose | Lines |
|------|---------|-------|
| `src/apiauth/cli.py` | Click CLI: generate, list, show, rotate, revoke, verify, import, export, audit, stats | ~520 |
| `src/apiauth/keystore.py` | AES-256-GCM encrypted storage, master key in `~/.apiauth/master.key` | ~200 |
| `src/apiauth/keygen.py` | Key/JWT generation, rotation, hashing | ~150 |
| `src/apiauth/verify.py` | Verification, expiry checking (valid/revoked/expired/expiring) | ~80 |
| `tests/test_cli.py` | 58 tests: unit + CLI integration (Click CliRunner) | ~350 |
| `pyproject.toml` | PEP 621 metadata, deps, optional deps, tool config | ~70 |

---

## Common Fix Patterns

| Issue Type | Typical Fix | Files |
|------------|-------------|-------|
| **CI failure (ruff)** | Fix lint error (unused import, line length, etc.) | `src/apiauth/*.py` |
| **CI failure (pytest)** | Fix test assertion or update test for behavior change | `tests/test_cli.py` |
| **Dependency outdated** | Update `pyproject.toml` deps, run `pip install -e ".[dev]"` | `pyproject.toml` |
| **Missing type hints** | Add type annotations (mypy strict mode not enforced yet) | `src/apiauth/*.py` |
| **CLI command broken** | Fix click command, add test in `TestCLIIntegration` | `src/apiauth/cli.py`, `tests/test_cli.py` |
| **Keystore encryption issue** | Check master key handling, AES-GCM nonce reuse | `src/apiauth/keystore.py` |

---

## Agent Conventions

| Convention | Rule |
|------------|------|
| **Branch naming** | `improve/apiauth-<timestamp>` (e.g., `improve/apiauth-20260630-143000`) |
| **Commit message** | `improve: <brief description>` (conventional commits) |
| **PR title** | `improve: <description>` |
| **PR body** | `Automated improvement by dev-engineer` |
| **Max lines changed** | ≤ 50 lines per PR |
| **Tests** | Must pass before PR; add test if fixing bug |

---

## Revenue Holdings Context (Business Awareness)

| Product | Subsidiary | Status |
|---------|------------|--------|
| CLI Revenue Tools (this repo) | Coding-Dev-Tools | ✅ Active |
| SaaS Churn Predictor | Revenue-Holdings | 🚧 Active |
| Autonomous Revenue Agent | Revenue-Holdings | 🚧 Active |
| Agent Memory Final | Revenue-Holdings | 🚧 Active |
| Envault CLI | Revenue-Holdings | 🚧 Active |

**North Star:** Generate revenue through CLI tools, SaaS products, and automated operations.

**License Model:** Free tier (5 keys) → Individual $12/mo (unlimited) → Team/Enterprise.

---

## Swarm Memory Vault

Cross-agent state persisted at:
```
C:\Users\home\OneDrive\Documents\GitHub\Obsidian Vault Local\
```
Write decision logs, error logs, and cycle logs to `MEMORY.md` in the vault for cross-agent awareness.

---

## Self-Improvement Schedule

| Check | Cadence | Action |
|-------|---------|--------|
| MineReflections | Weekly (Mon) | Read `LEARNING/REFLECTIONS/algorithm-reflections.jsonl` for failure patterns |
| PAIUpgrade | Bi-weekly (alt Mon) | Check `LEARNING/SYNTHESIS/` for upgrade proposals |
| AlgorithmUpgrade | Monthly | Run full algorithmic review |

Check `PAI/USER/BUSINESS/SELF-IMPROVEMENT-SCHEDULE.md` in vault for current status.

---

## Quick Reference: CLI Commands

```bash
apiauth generate api-key -n "Name" -s "service" -e 90
apiauth generate jwt -n "Name" -s "service" -e 30 -c role=admin
apiauth list [--service SVC] [--json-output] [--show-expired]
apiauth show <key-id>
apiauth verify <api-key> [--json-output]
apiauth import <api-key> -n "Name" -s "service"
apiauth rotate <key-id> [--expiry-days N]
apiauth revoke <key-id>
apiauth export --format env|dotenv|json|github-actions [--service SVC]
apiauth audit
apiauth stats
```

---

*Created by dev-engineer agent. Update as repo evolves.*