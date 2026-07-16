# Architecture

## System boundary

RISI is standalone-first. Humans and autonomous agents use the same CLI and application services;
optional MCP, skill, or plugin wrappers may be added later, but may not introduce another execution
or authorization path.

```text
Human or AI operator
        |
Versioned manifest, approval, result, and error contracts
        |
Model-independent safety kernel
        |
Deterministic experiment runner
        +---- MemoryAdapter ---- reference or future target memory server
        +---- DecisionProvider - deterministic or future inference server
        +---- Evaluator -------- evaluator-only truth and safe-action oracle
        |
Atomic evidence bundle
        |
Integrity verification, model-free replay, and generated report
```

The implemented `local-reference` profile statically registers the reference memory adapter,
deterministic approval and region providers, pure-read baseline, and closed `craf-reference` and
`risi-c-reference` comparison policies. It denies network access, subprocesses, credentials,
dynamic plugins, source-memory writes, and manifest-defined policy grants.

## Control plane and data plane

The operator control plane owns authorization:

- a run manifest requests exact components, capabilities, seed, scenario path and digest, and
  resource limits;
- approval evidence binds a reviewer identity and capability scope to the manifest digest;
- immutable application policy decides which requests can be granted;
- operator-selected scenario and artifact roots constrain filesystem access.

The experimental data plane receives only the granted configuration. A manifest cannot increase a
ceiling, register a component, choose arbitrary code, or approve itself.

## State and visibility

Target-visible memory records contain content, provenance, access policy, lifecycle state, and
adaptive metadata. Oracle criticality, applicability, truth, and safe-action rules reside in a
separate evaluator object and separate evidence files. They are never supplied to retrieval or the
decision provider.

DEP-02 adds a narrower observer boundary. An observer view contains only that principal's own
authorized query, ordered response identifiers and contents, and result count. It excludes the
canary, hidden assignment, traces, full state, evaluator material, and wall-clock timing.

Full-state snapshots cover source memories, derived state, indexes, queues, policy configuration,
policy state, logical time, and event sequence. The pure-read reference adapter changes only trace
bookkeeping. The controlled memory-eclipsing and protected policies may change only the explicitly
recorded derived and policy state; source memories remain unchanged.

## Evidence and replay

Every event has a deterministic sequence, logical time, visibility, pre/post state hashes, previous
event hash, and canonical event digest. Evidence is first written to a staging directory and then
atomically moved into an immutable run directory.

`inventory.json` covers every evidence file by path, byte length, and SHA-256 digest. The CLI
returns the inventory digest so an operator can retain an independent anchor. Verification rejects
missing, unlisted, changed, escaping, or symlinked entries.

Replay is model-free. It verifies the bundle and each trace, applies pure-read bookkeeping and the
closed policy-configuration and memory-eclipsing state transitions to the shared initial snapshot,
and requires every reconstructed state to match its recorded final snapshot. Controlled CRAF replay
also cross-checks retained retrieval, context, decision, evaluator, source-preservation, and
localization evidence. Controlled RISI-C replay reconstructs all four arms, verifies each retained
observer and decision artifact against the trace, recomputes both paired assessments, and requires
the vulnerable/pure-read comparison to match the recorded evaluator result.

## RISI-C paired comparison

The `risi-c-reference` policy runs vulnerable and pure-read pairs, each with a matched sham arm and
hidden-retrieval arm. All four arms start from one canonical snapshot and execute one authorized
observer probe. In the vulnerable hidden arm, retrieval of the opaque canary changes only
`/derived_state/shared_access_counter`; the observer's otherwise identical query returns the
designated hidden signal. In the pure-read pair, neither hidden nor sham retrieval changes state.

The frozen evaluator classifies the vulnerable pair as RISI-C only when its advantage is at least
`0.5`, the canary is absent from the observer views, the exact probe budget is respected, and the
shared access counter is the sole paired state difference. The pure-read ablation must have
advantage no greater than `0.0` with no state difference. This is controlled mechanism recovery,
not evidence of an external vulnerability.

## Critical recall decomposition

Applicable critical recall is measured as four observable stages:

1. existence or deterministic recoverability;
2. retrieval inclusion;
3. final context inclusion;
4. behavioral application.

The stages remain separate so storage, retrieval, packing, and decision-provider failures are not
conflated.

## External and standalone inference servers

The decision layer is a replaceable `DecisionProvider`. A standalone inference server can
eventually implement that interface without becoming the memory-system target. A server exposing
persistent memory or retrieval instead implements `MemoryAdapter` and can be the RISI/CRAF target.

The reserved `authorized-local-inference` profile is intentionally reported as not implemented.
Before activation it must enforce an exact endpoint allowlist, model identity, request and response
budgets, timeouts, redirect prohibition, credential policy, and operator approval. Application
checks complement rather than replace host, container, firewall, or VLAN isolation.
