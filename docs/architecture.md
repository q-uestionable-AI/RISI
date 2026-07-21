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
Deterministic budget ledger and experiment runner
        +---- MemoryAdapter -------- local deterministic reference
        +---- ExternalKnowledgeAdapter - closed isolated Dify Knowledge API
        +---- DecisionProvider - deterministic or future inference server
        +---- Evaluator -------- evaluator-only truth and safe-action oracle
        |
Atomic evidence bundle
        |
Verification, inspection, comparison, model-free replay, and generated report
```

The implemented `local-reference` profile statically registers the reference memory adapter,
deterministic approval and region providers, pure-read baseline, and closed `craf-reference` and
`risi-c-reference` comparison policies. It denies network access, subprocesses, credentials,
dynamic plugins, source-memory writes, and manifest-defined policy grants.

The additive `isolated-dify-knowledge` profile uses separate external-target, campaign, approval,
checkpoint, preflight, health, deviation, and result contracts. It does not change or extend a
schema-v1 `RunManifest`. Its safety decision binds an exact target-manifest digest, private-input
inventory digest, capability set, purpose, expiry, and attempt ceiling. E2 validation purpose cannot
authorize E1 execution; a full campaign requires an independently accepted E3 decision.

## Control plane and data plane

The operator control plane owns authorization:

- a run manifest requests exact components, capabilities, seed, scenario path and digest, and
  resource limits;
- approval evidence binds a reviewer identity and capability scope to the manifest digest;
- immutable application policy decides which requests can be granted;
- operator-selected scenario and artifact roots constrain filesystem access.

The experimental data plane receives only the granted configuration. A manifest cannot increase a
ceiling, register a component, choose arbitrary code, or approve itself.

The runner consumes an immutable deterministic ledger beneath the CLI. Episode starts, retrieval
calls, and decision proposals define logical steps; exact scenario bytes, source-memory records,
and finalized bundle bytes are also checked against the approved manifest. Exhaustion is a
machine-distinct engineering result and cannot produce a completed experimental bundle.

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

Campaign replay is also model-free but has a narrower purpose. It verifies the bundle inventory,
manifest/result identities, paired target-visible/evaluator record counts, and exact observation
total. It never contacts Dify or re-embeds a document. Repeating a target request would be a new
campaign attempt, not replay.

Inspection verifies a bundle before returning a closed run, manifest, scenario, policy, result,
resource, digest, and path summary. Comparison verifies both inputs before reporting exact equality
or stable differing evidence paths and semantic anchors. Caller provenance stays outside the
bundle, preserving byte equality between matched human and agent runs.

A completed run identifier is immutable. Re-invocation returns an existing result only when its
bundle verifies and its manifest digest matches. Incomplete, tampered, or differently bound final
paths are neither overwritten nor deleted. Staging directories are not evidence.

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

### Isolated Dify knowledge target

The implemented external adapter is a memory/retrieval target, not an inference provider. It uses
normal CA and hostname verification plus an exact peer-certificate SHA-256. The standard-library
transport accepts one origin, a closed method/path allowlist, ten-second requests, bounded JSON
responses, and zero automatic retries. Credentials are read only from a digest-bound
operator-controlled file and are excluded from renderings, errors, manifests, and evidence.

The adapter may create, inspect, and delete a knowledge base; create text documents; poll indexing;
inspect a document and its single enabled segment; run semantic-vector top-five retrieval; and read
the target health summary. Console, app, workflow, agent, upload, datasource, metadata-write,
model-management, plugin-management, database, vector, Ollama, callback, and arbitrary paths are
outside the transport allowlist.

The campaign service is synchronous but retains checkpoints and accepts cooperative cancellation.
Cancellation stops new requests, does not issue a compensating retry, and retains a deviation.
Target-visible scenario worlds and evaluator-only oracles are loaded from separate private files.

The decision layer is a replaceable `DecisionProvider`. A standalone inference server can
eventually implement that interface without becoming the memory-system target. A server exposing
persistent memory or retrieval instead implements `MemoryAdapter` and can be the RISI/CRAF target.

The reserved `authorized-local-inference` profile is intentionally reported as not implemented.
Before activation it must enforce an exact endpoint allowlist, model identity, request and response
budgets, timeouts, redirect prohibition, credential policy, and operator approval. Application
checks complement rather than replace host, container, firewall, or VLAN isolation.

The implemented local-reference A1 lifecycle remains one synchronous process with cooperative interruption and
zero automatic retries. Status services, active cancel commands, wall-clock experimental
deadlines, and asynchronous jobs remain denied for that contract. The separate campaign lifecycle
adds durable status and cancel records without changing local-reference behavior.
