# RISI

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

The repository implements a guarded deterministic reference path for the synthetic DEP-01
pure-read baseline. It includes:

- strict run, approval, scenario, result, event, state, and evidence contracts;
- a model-independent `local-reference` safety profile;
- authorized deterministic retrieval and a transport-neutral, replaceable decision-provider
  boundary;
- structurally separated target-visible and evaluator-only state;
- full-state snapshots and hash-chained event telemetry;
- atomic evidence bundles, integrity verification, model-free replay, and generated reports;
- stable text and JSON CLI output for human or autonomous operation.

It does **not** implement an attack, vulnerable adaptive policy, external inference integration,
database, consequential action, or external vulnerability finding. The authoritative research
charter and research evidence remain outside this repository in the private research vault.

Capability discovery reserves separate local/lab and remote public-HTTPS inference profiles for
future, separately approved work. Both remain non-executable: they grant no networking,
credentials, adapter registration, or model access in the implemented `local-reference` profile.

## Quickstart

```bash
uv sync --locked --group dev
uv run risi capabilities --format json
uv run risi validate scenarios/examples/dep-01-local-reference.manifest.json --approval scenarios/examples/dep-01-local-reference.approval.json --scenario-root scenarios
uv run risi run scenarios/examples/dep-01-local-reference.manifest.json --approval scenarios/examples/dep-01-local-reference.approval.json --scenario-root scenarios --artifact-root artifacts
uv run risi verify artifacts/dep-01-local-reference
uv run risi replay artifacts/dep-01-local-reference
uv run risi report artifacts/dep-01-local-reference
```

The manifest binds the exact scenario-file digest, and the example approval binds the exact
manifest digest. Approval records provide auditable provenance and change detection, not
authentication. Stronger deployments must protect or sign approvals outside an agent's execution
context.

## Safety boundary

RISI uses synthetic scenarios and lab-controlled or explicitly authorized systems only. Decision
outputs are proposals and must never be connected to live medical, financial, deployment,
identity, access-control, or other consequential production systems.

All models—including an orchestrating model—are treated as untrusted callers. The safety kernel
enforces profile, capability, budget, approval, and path controls below the CLI. The implemented
profile denies network access, subprocesses, credentials, dynamic plugins, and memory writes by
construction. Host or network isolation remains necessary when future external adapters are used.
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
  [risi.mintlify.site](https://risi.mintlify.site).
- `schemas/` contains versioned machine contracts.
- `scenarios/` contains reviewed synthetic examples.
- `artifacts/` is excluded from Git and contains local evidence bundles.

## License

RISI is licensed under the [Apache License 2.0](LICENSE).
