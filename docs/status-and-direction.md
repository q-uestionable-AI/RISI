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
- An unreleased additive `isolated-dify-knowledge` profile with pinned standard-library HTTPS,
  separate PBKDF2-SHA256 API and health credential verifiers, a closed Dify 1.15 Knowledge API
  allowlist,
  and zero retries.
- Exact external-target, campaign, approval, checkpoint, preflight, health, deviation, and result
  contracts with prepare, preflight, status, cancel, execute, inspect, verify, compare, and replay
  application services.
- Fixed E1 geometry checks for 330 worlds, 22 observations per world, 7,260 observations, and
  primary design power 0.8025. No campaign outcome is present in this repository.
- Public documentation deployed at <https://risi.q-uestionable.ai>.

## Current engineering boundary

The external-target code is bounded to the accepted Dify engineering profile. Target deployment,
immutable identities, integration evidence, and private input inventories live outside this public
repository. A full CRAF-T / CRAF-Ret campaign remains unavailable without a separately accepted E3
approval bound to the exact target manifest, campaign manifest, input inventory, preflight, evidence
path, expiry, and one-attempt limit.

The implemented A1 surface has no status service, active cancel command, wall-clock experimental
deadline, automatic retry, or asynchronous job. Cooperative interruption is machine-distinct and
does not finalize a partial bundle. The separate campaign lifecycle has durable status and
cooperative cancellation records but remains synchronous and has zero automatic retries.

Local or remote generative inference profiles, optional MCP or skill wrappers, broader defenses,
merge, release, publication, and claims remain separate conditional stages.

No reference-only result establishes an external vulnerability, general prevalence, or a validated
research claim.
