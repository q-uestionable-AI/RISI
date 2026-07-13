# Architecture

## Initial boundary

The scaffold establishes contracts without implementing a database, attack, external adapter, or
model call.

```text
Synthetic scenario and principals
        |
Trace runner and budget enforcement (future)
        |
MemoryAdapter contract
        |
Deterministic reference engine (future M1 work)
        |
Decision context and simulated decision agent (future)
        |
Separated attacker-visible and evaluator-only telemetry
```

## State and visibility

Target-visible memory records contain content, provenance, access policy, lifecycle state, and
adaptive metadata. Oracle criticality, applicability, truth, and safe-action rules belong to the
evaluator and must never enter retrieval or generation state.

Snapshots must eventually cover content, adaptive metadata, indexes, caches, logical time,
maintenance queues, consolidation state, and pending jobs. Content-only snapshots are insufficient.

## Critical recall decomposition

Applicable critical recall is measured as four observable stages:

1. existence or deterministic recoverability;
2. retrieval inclusion;
3. final context inclusion;
4. behavioral application.

The stages are measured separately so storage, retrieval, packing, and decision-model failures are
not conflated.

## Event integrity

Every state transition will emit a monotonic event linked to the previous event hash and pre/post
state hashes. The schema defines this contract now; cryptographic event construction and replay are
future M1 implementation work.
