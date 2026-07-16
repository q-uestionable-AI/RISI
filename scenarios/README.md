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

The DEP-01 examples include a pure-read baseline and a separately approval-bound controlled CRAF
comparison. The comparison uses only authorized truthful retrievals, preserves source memories,
and separates target-visible policy state from evaluator-only truth and criticality.

The DEP-02 example is a separately approval-bound controlled RISI-C comparison. It runs vulnerable
and pure-read sham/hidden pairs from one snapshot, limits the observer to one authorized query, and
keeps canary assignment, full state, traces, evaluator material, and timing outside the observer
view.
