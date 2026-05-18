# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Directory listing badges: Open Source Alternative, LibHunt, Awesome Python
- Sibling tool cross-links in README footer

### Changed

- CI security hardened: `persist-credentials: false`, restricted permissions
- Documentation branding updated from DevForge to Revenue Holdings
- README rewritten with pricing table, Why hook, Revenue Holdings branding
- Tool count corrected to 11
- Project URLs added to `pyproject.toml`
- CI badge corrected to reference ci.yml

### Fixed

- CI workflow: consolidated duplicate workflows, hardened security, updated actions
- CI publish workflow: downgraded actions/checkout@v6 and setup-python@v6 to v4/v5 (v6 does not exist)
- PyPI token check moved to job-level if (secrets context not available at step level)
- CI workflow simplified to avoid workflow parse failures
- UTF-8 encoding (mojibake) in file output
- Ruff lint issues: `datetime.UTC`, `X | None` syntax, `E501`, `B904`, `F821`
- Missing `ruff` dev dependency (caused CI `ruff: command not found`)
- Stray `verify.py` removed (logic lives in `keygen.py`)
- Tests updated for new `verify_api_key` return format (status instead of valid)

## [0.1.0] — 2025-05-17

### Added

- Initial beta release
- Core functionality
- CLI interface
- Test suite
- CI/CD workflows with ruff lint and pytest
- CONTRIBUTING.md
