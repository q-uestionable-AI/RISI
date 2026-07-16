# Security Policy

## Supported versions

RISI is pre-experimental. No release is currently supported for production use.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for implementation vulnerabilities in this repository.
Do not open a public issue containing exploit details, secrets, private research material, or
unreleased experimental traces.

Include the affected commit, reproduction conditions, expected behavior, observed behavior, and a
minimal synthetic reproducer when possible.

## Research authorization boundary

Only test systems you own, control, or are explicitly authorized to test. RISI research must use:

- synthetic identities, facts, policies, and canary secrets;
- lab-controlled or explicitly authorized systems;
- simulated decision outcomes;
- bounded, recorded experiment configurations.

Do not use RISI against real user memories, third-party accounts, or live consequential systems.
Do not store credentials in source, configuration, scenarios, or experiment artifacts.

## Harness trust model

Treat human-facing and agent-facing callers as equally untrusted. A model-generated manifest,
tool call, or explanation cannot grant authority or weaken a safety ceiling. The implemented
`local-reference` profile accepts only registered deterministic components and denies networking,
subprocesses, credentials, dynamic plugins, and memory writes.

Approval records bind provenance to an exact manifest hash, but an unsigned JSON file is not
authentication. Protect approval material outside the agent's writable context when stronger
separation is required. Application-level endpoint checks also do not replace container, host,
VLAN, or firewall egress controls.

Evidence bundles are content-addressed and tamper-evident. Retain the reported inventory SHA-256
outside the bundle when an independent integrity anchor is required.

## Responsible disclosure

Potential third-party defects must be reproduced from a clean state before disclosure. Prepare a
minimal private reproducer, affected-version analysis, and mitigation proposal, then coordinate
privately with the maintainer before publishing details.
