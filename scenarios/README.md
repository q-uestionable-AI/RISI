# Scenarios

Scenarios are synthetic, structured worlds used for RISI and CRAF reference episodes. They must:

- contain no real identities, secrets, accounts, or production data;
- keep evaluator-only oracles outside target-visible memory and decision state;
- declare principals, permissions, budgets, deterministic seeds, and an executable protocol;
- use machine-verifiable truth and decision rules;
- distinguish proposed or exploratory conditions from evidence-supported claims.

Executable scenario files are strict JSON and must conform to
`schemas/scenario.schema.json`. The loader also performs semantic checks such as canonical world
hash verification, seed authorization, referenced-memory existence, and input ceilings.

The bundle covers all ten synthetic scenario identifiers. DEP-01 and the eight DEP-03, DAT, MED,
FIN, and IAM scenarios have approval-bound pure-read fixtures. The narrow
`deterministic-obligation` provider proposes each scenario's safe action only when its required
current memory is retrieved; it performs no write or external action. DAT-02 and IAM-02 retain
combined-phenomenon design metadata but expose no executable RISI-C reference protocol.

The DEP-01 examples also include a separately approval-bound controlled CRAF comparison. The
comparison uses only authorized truthful retrievals, preserves source memories, and separates
target-visible policy state from evaluator-only truth and criticality.

The DEP-02 example is a separately approval-bound controlled RISI-C comparison. It runs vulnerable
and pure-read sham/hidden pairs from one snapshot, limits the observer to one authorized query, and
keeps canary assignment, full state, traces, evaluator material, and timing outside the observer
view.

Only the DEP-01 CRAF and DEP-02 RISI-C examples contain intentionally positive reference
mechanisms. The other fixtures are safe deterministic baselines for contract and taxonomy
validation. They are not external-system findings, attack variants, or authorization for a live or
consequential action.
