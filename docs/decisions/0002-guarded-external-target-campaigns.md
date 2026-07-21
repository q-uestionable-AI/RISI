# ADR 0002: Guard external-target campaigns with independent bound contracts

**Status:** Accepted for unreleased E2 implementation
**Date:** 2026-07-20

## Context

The deterministic reference harness cannot answer whether the proposed CRAF-T or CRAF-Ret behavior
is observable in a controlled persistent retrieval system. A real target introduces network,
credential, service-lifecycle, nondeterministic retrieval, and evidence-retention risks that the
`local-reference` run manifest does not represent.

## Decision

Add a separate `isolated-dify-knowledge` profile and `ExternalKnowledgeAdapter`. Do not reinterpret
the schema-v1 `local-reference` contract. An external execution requires three independent objects:

1. an external-target manifest that binds the HTTPS origin, normal CA/hostname validation, peer
   certificate digest, separate API-key and health-token fingerprints, exact Dify API paths,
   service identities, ten-second request deadline, one-second indexing poll, 300-second indexing
   limit, and zero retries;
2. a campaign manifest that binds the target digest, private-input inventory digest, geometry,
   retrieval settings, evidence location, expiry, and whether the work is validation-only; and
3. a human approval that binds both manifests, the input inventory, exact capabilities, purpose,
   expiry, and attempt ceiling.

The safety kernel grants the intersection only when every binding matches. E2 validation authority
cannot authorize a full E1 campaign. Full execution requires an accepted `E3-` decision. Every
state-changing CLI operation calls the same application service and safety decision.

Use only standard-library HTTPS with normal CA and hostname verification plus the exact peer
certificate digest. Allow only the frozen Dify 1.15 knowledge operations and one health endpoint.
Never retry automatically. Preserve target-visible observations and evaluator assessments in
separate inventoried files. Finalize evidence atomically; cancellation prevents new calls and
retains a non-overwriting deviation.

## Consequences

- The existing release contract and deterministic reference fixtures remain compatible.
- A manifest cannot grant arbitrary URLs, plugins, credentials, models, or network reachability.
- Target state is nondeterministic evidence; replay verifies retained identities, counts, and
  assessments without repeating a target call.
- Host firewall, VLAN, container, certificate, secret ACL, image, model, and plugin controls remain
  deployment responsibilities outside this public repository.
- The adapter and campaign machinery do not establish a Dify vulnerability, authorize E3, or make
  a release or publication decision.
