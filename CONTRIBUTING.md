# Contributing to RISI

## Development setup

```bash
git clone https://github.com/q-uestionable-AI/RISI.git
cd RISI
uv sync --locked --group dev
uv run pre-commit install
```

## Branch workflow

Do not develop directly on `main`. Create a coherent `feature/*` or `fix/*` branch, verify the
complete approved outcome, and keep it on that branch until it is release-ready.

## Before committing

Run:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src/risi/
uv run pytest -q
uv run bandit -r src/ -c pyproject.toml
uv run pip-audit
uv run pre-commit run --all-files
uv run risi --help
```

## Code standards

- Python 3.11 through 3.13.
- Google-style docstrings on public classes, methods, and functions.
- Type hints on all public signatures.
- 100-character line length.
- Synthetic, deterministic fixtures only.
- No credentials, private charter content, or research evidence in the repository.
- Stable JSON contracts for operations intended to be invoked autonomously.
- Identical safety authorization below every human-facing or agent-facing interface.

## Research claims

Label proposed terminology, hypotheses, preliminary evidence, and established evidence accurately.
Do not claim that a synthetic effect demonstrates real-world prevalence or a general vulnerability.

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0.
