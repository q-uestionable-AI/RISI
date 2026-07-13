# RISI

RISI is a pre-experimental security research project studying **Retrieval-Induced State
Interference** and **Critical Recall Availability Failure** in persistent AI-agent memory.

The project distinguishes:

- **RISI**: retrieval changes shared or future-relevant adaptive memory state.
- **RISI-C**: an authorized observer can distinguish hidden retrieval activity through those
  state changes.
- **CRAF**: a valid, applicable critical memory is not retrieved or behaviorally applied after a
  bounded sequence of authorized, truthful, non-instructional interactions.
- **Memory eclipsing**: truth-preserving suppression of a critical memory without corrupting or
  directly deleting it.

These are proposed terms and hypotheses, not validated findings. Critical Admission Availability
Failure (CAAF) is tracked separately as an exploratory admission-stage phenomenon and is not core
CRAF.

## Status

The repository is at the initial scaffold stage. It does not yet implement attacks, defenses, a
database, external adapters, or an experimental evidence pipeline. The authoritative research
charter is maintained separately in the private research vault and is not stored in this
repository.

## Safety boundary

RISI uses synthetic scenarios and lab-controlled or explicitly authorized systems only. It must
not be connected to live medical, financial, deployment, identity, access-control, or other
consequential production systems.

## Development

RISI follows the same release-aligned Python development framework used by CTPF Research Harness.

```bash
uv sync --locked --group dev
uv run risi --help
uv run pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) for the full workflow.

## Documentation

- `docs/` contains repository engineering documentation and decision records.
- `documentation/` contains the Mintlify-ready public documentation source.
- `schemas/` contains machine-readable scenario and event contracts.

## License

RISI is licensed under the [Apache License 2.0](LICENSE).
