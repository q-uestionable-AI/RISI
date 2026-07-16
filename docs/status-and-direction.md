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
- Controlled DEP-01 memory-eclipsing and protected-critical-recall comparison.
- Evaluator-only CRAF classification and loss-of-influence localization.
- Atomic evidence bundles, verification, model-free replay, and reports.
- Stable JSON CLI surface for autonomous operation.
- Public documentation deployed at <https://risi.q-uestionable.ai>.

## Next direction

After the controlled DEP-01 branch passes its review and evidence gate, the next proposed research
implementation is the separately approved DEP-02 RISI-C reference mechanism. External adapters,
local inference servers, optional MCP or skill wrappers, broader defenses, and publication work
remain later conditional stages.

No reference-only result establishes an external vulnerability, general prevalence, or a validated
research claim.
