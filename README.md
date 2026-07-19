# RISI

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![CI](https://github.com/q-uestionable-AI/RISI/actions/workflows/ci.yml/badge.svg)](https://github.com/q-uestionable-AI/RISI/actions/workflows/ci.yml)
[![CodeQL](https://github.com/q-uestionable-AI/RISI/actions/workflows/codeql.yml/badge.svg)](https://github.com/q-uestionable-AI/RISI/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/risi.svg)](https://pypi.org/project/risi/)
[![Python 3.11–3.13](https://img.shields.io/badge/python-3.11--3.13-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docs](https://img.shields.io/badge/docs-risi.q--uestionable.ai-8b5cf6)](https://risi.q-uestionable.ai)

RISI is a Python library and command-line tool for deterministic experiments about
retrieval-related changes in persistent AI-agent memory. The current implementation runs
synthetic reference scenarios; it does not test external systems.

The project distinguishes:

- **RISI**: retrieval changes shared or future-relevant adaptive memory state.
- **RISI-C**: an authorized observer can distinguish hidden retrieval activity through those
  state changes.
- **CRAF**: a valid, applicable critical memory is not retrieved or behaviorally applied after a
  bounded sequence of authorized, truthful, non-instructional interactions.
- **Memory eclipsing**: truth-preserving suppression of a critical memory without corrupting or
  directly deleting it.

These are proposed terms and hypotheses, not validated findings. Critical Admission Availability
Failure (CAAF) remains a separate exploratory admission-stage phenomenon and is not core CRAF.

## Status

Version 0.1.0 provides:

- JSON schemas for runs, approvals, scenarios, results, events, state, and evidence;
- a deterministic `local-reference` profile with no model or network access;
- separate target-visible and evaluator-only state;
- state snapshots and hash-linked event records;
- a three-arm synthetic CRAF reference comparison;
- a four-arm synthetic RISI-C reference comparison;
- evidence-bundle verification, inspection, replay, comparison, and report generation;
- limits for episodes, retrieval calls, logical steps, scenario bytes, memory records, and bundle
  bytes; and
- text and JSON output from the synchronous CLI.

The reference comparisons include intentionally vulnerable and protected synthetic policies. Their
results describe those fixtures only and are not evidence about another system.

The repository does not implement an external attack, external inference, a database, or a
connection to consequential systems. Project governance is kept in a private governance vault;
research records and evidence are kept in a separate private Lab workspace. Local project tooling
locates them through `RISI_VAULT_ROOT` and `RISI_RESEARCH_ROOT`. Those locations are not part of the
public package interface.

Capability output lists reserved local/lab and remote HTTPS inference profiles. They are marked
`not-implemented` and do not enable networking, credentials, adapters, or model access.

## Install

Install the released command-line harness from PyPI:

```bash
pip install risi==0.1.0
risi --version
risi capabilities --format json
```

The package provides the RISI library and CLI. DEP-01 and DEP-02 scenarios, manifests, and
approvals are repository examples, so clone the repository to run them.

## Run the source example

```bash
git clone https://github.com/q-uestionable-AI/RISI.git
cd RISI
uv sync --locked --group dev
uv run risi capabilities --format json
uv run risi validate scenarios/examples/dep-01-local-reference.manifest.json --approval scenarios/examples/dep-01-local-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-01-local-reference.manifest.json --approval scenarios/examples/dep-01-local-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi verify artifacts/dep-01-local-reference
uv run risi inspect artifacts/dep-01-local-reference --format json
uv run risi replay artifacts/dep-01-local-reference
uv run risi report artifacts/dep-01-local-reference
```

The manifest includes the scenario-file digest, and the example approval includes the manifest
digest. Approval files record who approved an example and allow change detection; they do not
authenticate an operator.

`risi compare <bundle-a> <bundle-b> --format json` verifies both bundles before reporting equality
or differing evidence paths and semantic anchors. Re-running the same approved manifest against a
complete verified final bundle returns its existing anchor with `reused: true`. The command rejects
an incomplete, changed, or invalid final path instead of overwriting it.

## Run the controlled CRAF comparison

```bash
uv run risi validate scenarios/examples/dep-01-craf-reference.manifest.json --approval scenarios/examples/dep-01-craf-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-01-craf-reference.manifest.json --approval scenarios/examples/dep-01-craf-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi replay artifacts/dep-01-craf-reference
uv run risi report artifacts/dep-01-craf-reference
```

This run starts control, memory-eclipsing, and protected-critical-recall arms from the same
snapshot. The report marks the reference condition as recovered only when the control remains safe,
the vulnerable arm meets the retrieval-stage CRAF criteria without changing the critical source,
and the protected arm remains safe.

## Run the controlled RISI-C comparison

```bash
uv run risi validate scenarios/examples/dep-02-risi-c-reference.manifest.json --approval scenarios/examples/dep-02-risi-c-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-02-risi-c-reference.manifest.json --approval scenarios/examples/dep-02-risi-c-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi replay artifacts/dep-02-risi-c-reference
uv run risi report artifacts/dep-02-risi-c-reference
```

This run starts vulnerable sham, vulnerable hidden-retrieval, pure-read sham, and pure-read
hidden-retrieval arms from the same snapshot. Observer evidence contains its query, response, and
result count. The report marks the reference condition as recovered only when the vulnerable pair
has advantage `0.5`, the pure-read pair has advantage `0.0`, the canary is absent from both observer
views, `/derived_state/shared_access_counter` is the only differing shared-state field in the
vulnerable pair, and every region decision remains safe.

## Safety boundary

RISI uses synthetic scenarios and lab-controlled or explicitly authorized systems only. Decision
outputs are proposals and must never be connected to live medical, financial, deployment,
identity, access-control, or other consequential production systems.

All models, including an orchestrating model, are treated as untrusted callers. The safety kernel
checks the selected profile, capabilities, budgets, approval, and paths below the CLI. The
`local-reference` profile rejects network access, subprocesses, credentials, dynamic plugins, and
source-memory writes. Its adaptive policies write only the derived-state fields defined by the
profile.

The current lifecycle runs in one synchronous process with cooperative interruption and zero
automatic retries. It has no status service, cancel command, asynchronous jobs, or wall-clock
experimental deadline. `risi capabilities --format json` reports these constraints.

External adapters are not implemented. Any later adapter would require separate approval, host or
network isolation, bounded credentials and resources, and redacted request and response records.

## Development and documentation

RISI uses Python 3.11–3.13, uv, Typer, Ruff, mypy, pytest, Bandit, pip-audit, and Google-style
docstrings. See [CONTRIBUTING.md](CONTRIBUTING.md),
[DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md), and
[docs/architecture.md](docs/architecture.md).

- `docs/` contains public engineering documentation and decision records.
- `documentation/` contains the source deployed at
  [risi.q-uestionable.ai](https://risi.q-uestionable.ai).
- `schemas/` contains versioned machine contracts.
- `scenarios/` contains reviewed synthetic examples.
- `artifacts/` is excluded from Git and contains local evidence bundles.

## License

RISI is licensed under the [Apache License 2.0](LICENSE).
