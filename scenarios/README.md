# Scenarios

Scenarios are synthetic, structured worlds used for paired RISI and CRAF episodes. They must:

- contain no real identities, secrets, accounts, or production data;
- keep evaluator-only oracles outside target-visible memory state;
- declare principals, permissions, attack budgets, and deterministic seeds;
- use machine-verifiable truth and decision rules;
- distinguish proposed or exploratory conditions from headline evidence conditions.

Scenario files must validate against `schemas/scenario.schema.json`. Initial examples will be added
only after the scenario contract and truth-validation approach are approved.
