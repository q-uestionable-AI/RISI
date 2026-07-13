# Development workflow

## Release alignment

RISI follows a release-aligned workflow:

- `main` represents the latest released and tagged version.
- active development remains on short-lived branches;
- user-facing documentation on `main` describes released behavior;
- tags, package metadata, and public documentation remain aligned.

## Branches

- `feature/*` — new functionality.
- `fix/*` — corrections.
- `docs/*` — optional documentation-only work.
- `chore/*` — optional maintenance work.

Branch from `main`, keep the scope focused, and merge only when the work is ready for release.

## Research change control

Engineering changes must not silently alter research definitions, threat models, primary outcomes,
budgets, or evidence gates. Record durable design decisions under `docs/decisions/`. Research
protocol and evidence remain in their authorized private locations rather than this repository.

## Verification

Before a commit or release, run the complete command set documented in `CONTRIBUTING.md`. At a
minimum, the CLI help and smoke commands must work on a clean locked environment.

## Releases

Release automation will be added only after the package name, license, release environment, and
trusted PyPI publishing configuration are approved. Never publish from a dirty tree, an untagged
commit, or a non-release branch.
