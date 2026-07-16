# Status and direction

This is a public implementation summary, not the research plan. The authoritative charter,
session-to-session plan, evidence gates, and spending decisions remain in the private research
vault.

## Implemented

- Cross-platform Python packaging and qai-aligned CI quality gates.
- Strict scenario, state, event, decision, operator, and evidence contracts.
- Full-state snapshots and hash-chained trace verification.
- Model-independent local-reference safety policy.
- Deterministic reference adapter and decision-provider boundary.
- Guarded DEP-01 pure-read baseline.
- Atomic evidence bundles, verification, model-free replay, and reports.
- Stable JSON CLI surface for autonomous operation.
- Mintlify-ready documentation source, not yet deployed.

## Next direction

The next research implementation is the approved adaptive-policy comparison for DEP-01, with
paired controls and evidence gates defined outside this repository. External adapters, local
inference servers, optional MCP or skill wrappers, defenses, and publication work remain later
conditional stages.

No reference-only result establishes an external vulnerability, general prevalence, or a validated
research claim.
