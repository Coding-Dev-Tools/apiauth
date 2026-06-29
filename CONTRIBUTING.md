# Contributing

Thanks for your interest in contributing!

## Development Setup

1. Fork and clone the repo
2. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
3. Install dev dependencies: `pip install -e ".[dev]"`
4. Run tests: `pytest tests/ -v`
5. Lint: `ruff check src/`

## Pull Requests

- Fork the repo and create a feature branch
- Add tests for any new functionality
- Ensure all existing tests pass
- Run `ruff check src/ --fix` before committing
- Keep PRs focused on a single change
- Ensure CI passes (ruff lint, pytest, CLI checks)

## Reporting Issues

- Use GitHub Issues
- Include Python version, OS, and steps to reproduce
- Include relevant error output

## Code Style

- Python 3.10+
- Type hints where practical
- Follow ruff defaults (Black-compatible formatting)
- Use conventional commits for commit messages (feat:, fix:, docs:, chore:, refactor:, test:)

## Testing

- Write unit tests for new functions in `tests/test_cli.py`
- Run full test suite: `pytest tests/ -v --tb=short`
- Target: 100% coverage for new code

## Security

- Never commit secrets or API keys
- Use `pip audit` before adding dependencies
- Follow the security practices in SECURITY.md

## License

By contributing, you agree your work will be licensed under the same license as this project (MIT).
