# apiauth

## Purpose
CLI tool for API key and JWT lifecycle management with encrypted local store — generate, store, verify, rotate, and revoke keys with an encrypted local keystore.

## Build & Test Commands
- Install: `pip install -e .` or `pip install apiauth`
- Test: `pytest tests/` (or `python -m pytest tests/ -v --tb=short`)
- Lint: `ruff check src/ --target-version py310`
- Build: `pip wheel . --wheel-dir dist/`
- CLI check: `apiauth --version && apiauth --help`

## Architecture
Key directories:
- `src/apiauth/` — Main package (CLI, keystore, crypto, commands)
- `tests/` — Test suite
- `.github/workflows/` — CI/CD (auto-code-review.yml, ci.yml, publish.yml)
- `dist/` — Built distributions

## Conventions
- Language: Python 3.10+
- Test framework: pytest
- CI: GitHub Actions (matrix: Python 3.10, 3.11, 3.12, 3.13)
- Linting: ruff (line-length 120, target py310)
- Formatting: ruff
- Package layout: src/ layout with setuptools
- Type checking: py.typed included
- Dependencies: click, cryptography, pyjwt, rich, python-dateutil
- CLI entry point: apiauth.cli:cli
- Master branch: master
