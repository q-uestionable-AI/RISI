# 0001 — Standalone, agent-operable, human-governed harness

- Date: 2026-07-16
- Status: accepted

## Context

RISI experiments should benefit from autonomous AI speed and interpretation while preserving human
authorization, reproducibility, and safe operation. MCP servers, skills, and plugins can improve
ergonomics but are ecosystem-specific and can accidentally create alternate authority paths.

## Decision

The standalone Python application and CLI are the primary product boundary. Human and AI operators
receive the same versioned JSON contracts and call the same application service. Every
state-changing request passes through a model-independent safety kernel before an adapter, decision
provider, filesystem writer, or future network client is reached.

All models, including an orchestrator, are untrusted callers. Manifests request capabilities but do
not grant them. Human approval evidence is bound to exact manifest material. Optional MCP, skill,
plugin, or other integrations must remain thin wrappers over the standalone service.

## Consequences

- Research automation is portable across agent ecosystems.
- Manual validation remains available through the same CLI and evidence.
- Guardrails do not depend on a frontier model's own safety behavior.
- Strong approval authentication and network isolation still require controls outside unsigned JSON
  and application code.
- Standalone inference servers remain possible through decision-provider or memory-adapter
  implementations under separately approved profiles.
