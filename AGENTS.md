# RISI — Agent Context

Repository-local instructions for coding agents. Do not create a parallel agent-instruction file.

RISI is a pre-experimental security research project for Retrieval-Induced State Interference
(RISI), RISI confidentiality failures (RISI-C), and Critical Recall Availability Failure (CRAF).
The authoritative research charter is maintained separately in the private research vault and
must never be copied into this repository.

## Operating rules

- Work in plan/approve mode. Read relevant files, state the plan, and wait for approval before
  editing files or performing Git actions.
- Verify repository behavior rather than relying on memory.
- Do not commit or push unless the user explicitly asks.
- Do not add dependencies without explicit approval.
- Keep research evidence, unpublished traces, findings, and publication drafts outside this repo.
- Build the complete, coherent, proportionate solution needed for the approved outcome. Do not
  reduce correctness, safety, verification, or documentation merely to minimize a change set.

## Research boundaries

- Use synthetic scenarios and lab-controlled or explicitly authorized systems only.
- Never connect decision outputs to live consequential systems.
- Keep RISI/CRAF conceptually separate from the CTPF Research Harness and its Capability Trust
  Propagation Failure work.
- Treat CAAF as exploratory and separate from core CRAF.
- Do not describe hypotheses or proposed terminology as validated findings.
- Keep evaluator-only truth, criticality, and applicability oracles outside target-visible state.
- Treat every model, including an orchestrating model, as an untrusted caller.
- Route every state-changing interface through the same model-independent safety kernel. CLI,
  MCP, skill, plugin, or other wrappers must not create alternate authority paths.
- Manifests may request capabilities but must never define their own grants or safety ceilings.

## Technical stack

- Python `>=3.11,<3.14`
- Package manager: uv with PEP 735 development groups
- Package layout: `src/risi/`
- CLI: Typer
- Build backend: Hatchling
- Lint and format: Ruff, 100-character lines
- Types: mypy
- Tests: pytest, pytest-asyncio, and pytest-timeout
- Docstrings: Google style on all public classes, methods, and functions
- Cross-platform: Windows, macOS, and Linux

## Coding standards

- Type hints are required on public signatures.
- Prefer guard clauses and keep functions focused.
- Use `pathlib.Path` for file paths.
- Use context managers for resources requiring cleanup.
- Do not suppress errors silently.
- Keep evaluator-only and attacker-visible data structurally separate.
- Use deterministic logical time in reference experiments; do not depend on wall-clock time.
- Avoid mutable global state and magic values.

## Core commands

```bash
uv sync --locked --group dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src/risi/
uv run pytest -q
uv run bandit -r src/ -c pyproject.toml
uv run pip-audit
uv run pre-commit run --all-files
uv run risi --help
```

## Git workflow

- `main` is release-aligned.
- Use `feature/*` for new functionality and `fix/*` for corrections.
- Keep unreleased code and documentation on the feature branch.
- Tag and publish only from a clean, release-aligned `main` commit.

## Cursor Cloud specific instructions

- This project is a self-contained Python CLI (`risi`); there is no server, database, or GUI. The
 startup update script runs `uv sync --locked --group dev`, so dependencies are already installed.
- All commands run through `uv run` (see `## Core commands`); `uv` is installed at `~/.local/bin`
 and on `PATH` via the login profile.
- `risi run` writes an immutable evidence bundle under `--artifact-root` (default example:
 `artifacts/<run-id>`). Re-running the same run ID fails with `artifact_failure: evidence bundle
 already exists`. To re-run, delete that bundle (or the gitignored `artifacts/` directory) first;
 `verify`, `replay`, and `report` are safe to repeat against an existing bundle.
- End-to-end smoke of the harness: `uv run risi run <manifest> --approval <approval>
 --scenario-root scenarios --artifact-root artifacts` then `verify`/`replay`/`report` on the
 resulting bundle (example manifests live in `scenarios/examples/`).
