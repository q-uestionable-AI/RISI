# Status and direction

This is a public implementation summary, not the research plan. The authoritative charter,
session-to-session plan, evidence gates, and spending decisions remain in the private research
governance vault. Research records and evidence live separately in the private Lab research
workspace configured by the operator.

## Implemented

- Cross-platform Python packaging and qai-aligned CI quality gates.
- Strict scenario, state, event, decision, operator, and evidence contracts.
- Full-state snapshots and hash-chained trace verification.
- Model-independent local-reference safety policy.
- Deterministic reference adapter and decision-provider boundary.
- Guarded DEP-01 pure-read baseline.
- Controlled DEP-01 memory-eclipsing and protected-critical-recall comparison.
- Evaluator-only CRAF classification and loss-of-influence localization.
- Controlled DEP-02 RISI-C comparison with matched sham/hidden arms and a pure-read ablation.
- Strict observer-only evidence, frozen classification, and sole-mediator state-difference proof.
- Atomic evidence bundles, verified inspection and comparison, model-free replay, and reports.
- Deterministic approved/consumed accounting for all six local-reference resources.
- Idempotent completed-run reuse with fail-closed incomplete, tampered, or manifest-mismatched
  final paths.
- Stable JSON CLI lifecycle discovery, including synchronous A1 support and hard denials.
- Public documentation deployed at <https://risi.q-uestionable.ai>.

## Next direction

The next decision is whether the deterministic DEP-01 and DEP-02 reference evidence is sufficient
to close the current M1 mechanism-recovery gate or needs additional local controls. External
adapters, local inference servers, optional MCP or skill wrappers, broader defenses, and
publication work remain later conditional stages.

The implemented A1 surface has no status service, active cancel command, wall-clock experimental
deadline, automatic retry, or asynchronous job. Cooperative interruption is machine-distinct and
does not finalize a partial bundle.

No reference-only result establishes an external vulnerability, general prevalence, or a validated
research claim.
