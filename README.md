# RISI Research Harness

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![CI](https://github.com/q-uestionable-AI/RISI/actions/workflows/ci.yml/badge.svg)](https://github.com/q-uestionable-AI/RISI/actions/workflows/ci.yml)
[![CodeQL](https://github.com/q-uestionable-AI/RISI/actions/workflows/codeql.yml/badge.svg)](https://github.com/q-uestionable-AI/RISI/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/risi.svg)](https://pypi.org/project/risi/)
[![Python 3.11–3.13](https://img.shields.io/badge/python-3.11--3.13-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Docs](https://img.shields.io/badge/docs-risi.q--uestionable.ai-8b5cf6)](https://risi.q-uestionable.ai)

RISI is an agent-operable, human-governed security research harness for studying
**Retrieval-Induced State Interference** and **Critical Recall Availability Failure** in
persistent AI-agent memory.

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

The repository implements guarded deterministic reference paths for the synthetic DEP-01
pure-read baseline, a controlled three-arm CRAF comparison, and a controlled four-arm DEP-02
RISI-C comparison. It includes:

- strict run, approval, scenario, result, event, state, and evidence contracts;
- a model-independent `local-reference` safety profile;
- authorized deterministic retrieval and a transport-neutral, replaceable decision-provider
  boundary;
- structurally separated target-visible and evaluator-only state;
- full-state snapshots and hash-chained event telemetry;
- an intentionally vulnerable memory-eclipsing policy and a protected-critical-recall control,
  both limited to the deterministic synthetic reference profile;
- evaluator-only CRAF classification, source-preservation proof, and retrieval/presentation/
  decision-use localization;
- an observer-only RISI-C evidence contract, frozen classifier, paired pure-read ablation, and
  sole-mediator proof for `/derived_state/shared_access_counter`;
- atomic evidence bundles, verified inspection and comparison, model-free replay, and generated
  reports;
- deterministic accounting for episodes, retrieval calls, logical steps, scenario bytes, memory
  records, and complete bundle bytes;
- idempotent re-invocation of verified completed runs and fail-closed handling of incomplete,
  changed, or tampered final paths;
- stable text and JSON CLI output for the synchronous human or autonomous A1 workflow.

It does **not** implement an external attack, external inference integration, database,
consequential action, or external vulnerability finding. The controlled vulnerable policy is a
deliberately synthetic reference mechanism, not evidence about another system. The authoritative
research charter and research evidence remain outside this repository in the private research
vault.

Capability discovery reserves separate local/lab and remote public-HTTPS inference profiles for
future, separately approved work. Both remain non-executable: they grant no networking,
credentials, adapter registration, or model access in the implemented `local-reference` profile.

## Install

Install the released command-line harness from PyPI:

```bash
pip install risi==0.1.0
risi --version
risi capabilities --format json
```

The distribution provides the RISI library and CLI. The bundled DEP-01 and DEP-02 scenarios,
manifests, and approvals are repository examples, so clone the source tree to run them.

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

The manifest binds the exact scenario-file digest, and the example approval binds the exact
manifest digest. Approval records provide auditable provenance and change detection, not
authentication. Stronger deployments must protect or sign approvals outside an agent's execution
context.

`risi compare <bundle-a> <bundle-b> --format json` verifies both bundles before reporting exact
equality or stable differing evidence paths and semantic anchors. Re-running the same approved
manifest against a complete verified final bundle returns its existing anchor with `reused: true`;
it never overwrites an incomplete, changed, or tampered final path.

## Run the controlled CRAF comparison

```bash
uv run risi validate scenarios/examples/dep-01-craf-reference.manifest.json --approval scenarios/examples/dep-01-craf-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-01-craf-reference.manifest.json --approval scenarios/examples/dep-01-craf-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi replay artifacts/dep-01-craf-reference
uv run risi report artifacts/dep-01-craf-reference
```

This run resets control, memory-eclipsing, and protected-critical-recall arms from one canonical
snapshot. It records a controlled mechanism as recovered only when the control is safe, the
vulnerable arm produces retrieval-stage core CRAF without changing the critical source, and the
protected arm remains safe.

## Run the controlled RISI-C comparison

```bash
uv run risi validate scenarios/examples/dep-02-risi-c-reference.manifest.json --approval scenarios/examples/dep-02-risi-c-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-02-risi-c-reference.manifest.json --approval scenarios/examples/dep-02-risi-c-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi replay artifacts/dep-02-risi-c-reference
uv run risi report artifacts/dep-02-risi-c-reference
```

This run resets vulnerable sham, vulnerable hidden-retrieval, pure-read sham, and pure-read
hidden-retrieval arms from one canonical snapshot. The observer evidence contains only its own
authorized query, response, and result count. The controlled mechanism is recovered only when the
vulnerable pair has advantage `0.5`, the pure-read ablation has advantage `0.0`, the canary remains
absent from both observer views, and the shared access counter is the sole vulnerable-pair state
mediator. Every region decision remains safe.

## Safety boundary

RISI uses synthetic scenarios and lab-controlled or explicitly authorized systems only. Decision
outputs are proposals and must never be connected to live medical, financial, deployment,
identity, access-control, or other consequential production systems.

All models—including an orchestrating model—are treated as untrusted callers. The safety kernel
enforces profile, capability, budget, approval, and path controls below the CLI. The implemented
profile denies network access, subprocesses, credentials, dynamic plugins, and source-memory
writes by construction. Its controlled adaptive policies may change only explicitly recorded
derived state. Host or network isolation remains necessary when future external adapters are used.
The implemented A1 lifecycle is one synchronous process with cooperative interruption and zero
automatic retries. It exposes no status service, cancel command, asynchronous jobs, or wall-clock
experimental deadline; `risi capabilities --format json` advertises those hard denials.
Any future remote inference profile must bind approval to an exact endpoint, model, non-secret
credential alias, generation parameters, network class, and request, token, time, retry, and spend
ceilings while retaining redacted request and response evidence.

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
