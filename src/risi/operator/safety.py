"""Model-independent authorization for every state-changing RISI operation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from risi.canonical import JsonValue
from risi.operator.models import (
    ApprovalRecord,
    Capability,
    ExecutionLimits,
    ExecutionProfile,
    RunManifest,
)


class PathBoundaryError(ValueError):
    """Raised when a requested path escapes an operator-controlled root."""


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Contain immutable grants and ceilings for an execution profile.

    Attributes:
        profile: Profile governed by this policy.
        capabilities: Maximum grantable capabilities.
        adapter: Only registered memory adapter allowed by the profile.
        decision_provider: Only registered decision provider allowed by the profile.
        policy: Only registered memory policy allowed by the profile.
        ceilings: Non-negotiable resource ceilings.
    """

    profile: ExecutionProfile
    capabilities: frozenset[Capability]
    adapter: str
    decision_provider: str
    policy: str
    ceilings: ExecutionLimits

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable profile capabilities."""
        capabilities = cast(
            list[JsonValue], sorted(capability.value for capability in self.capabilities)
        )
        return {
            "profile": self.profile.value,
            "capabilities": capabilities,
            "adapter": self.adapter,
            "decision_provider": self.decision_provider,
            "policy": self.policy,
            "ceilings": self.ceilings.to_json(),
            "network": "denied",
            "subprocesses": "denied",
            "credentials": "denied",
            "dynamic_plugins": "denied",
        }


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Record a safety-kernel allow or deny decision.

    Attributes:
        allowed: Whether execution is authorized.
        reason_codes: Stable denial reasons, empty when allowed.
        granted_capabilities: Capabilities granted after intersection with policy.
    """

    allowed: bool
    reason_codes: tuple[str, ...]
    granted_capabilities: tuple[Capability, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable authorization decision."""
        return {
            "allowed": self.allowed,
            "reason_codes": list(self.reason_codes),
            "granted_capabilities": [item.value for item in self.granted_capabilities],
        }


LOCAL_REFERENCE_POLICY = SafetyPolicy(
    profile=ExecutionProfile.LOCAL_REFERENCE,
    capabilities=frozenset(
        {
            Capability.SCENARIO_READ,
            Capability.ARTIFACT_WRITE,
            Capability.REFERENCE_EXECUTE,
            Capability.EVIDENCE_VERIFY,
        }
    ),
    adapter="reference",
    decision_provider="deterministic-approval",
    policy="pure-read",
    ceilings=ExecutionLimits(
        episodes=1,
        retrieval_calls=8,
        logical_steps=100,
        input_bytes=1_000_000,
        memory_records=1_000,
        artifact_bytes=20_000_000,
    ),
)

CRAF_REFERENCE_POLICY = SafetyPolicy(
    profile=ExecutionProfile.LOCAL_REFERENCE,
    capabilities=LOCAL_REFERENCE_POLICY.capabilities,
    adapter="reference",
    decision_provider="deterministic-approval",
    policy="craf-reference",
    ceilings=ExecutionLimits(
        episodes=3,
        retrieval_calls=6,
        logical_steps=100,
        input_bytes=1_000_000,
        memory_records=1_000,
        artifact_bytes=20_000_000,
    ),
)


def safety_policy_for_manifest(manifest: RunManifest) -> SafetyPolicy:
    """Select a closed built-in policy for an operator manifest.

    Args:
        manifest: Requested run contract.

    Returns:
        Exact immutable safety policy. Unknown policies fall back to the pure-read policy and are
        denied by the normal contract comparison.
    """
    if manifest.policy == CRAF_REFERENCE_POLICY.policy:
        return CRAF_REFERENCE_POLICY
    return LOCAL_REFERENCE_POLICY


def authorize_run(
    manifest: RunManifest,
    approval: ApprovalRecord | None,
    policy: SafetyPolicy | None = None,
) -> AuthorizationDecision:
    """Authorize an exact manifest under a non-agent-controlled policy.

    Args:
        manifest: Requested run contract.
        approval: Hash-bound approval evidence, if supplied.
        policy: Optional immutable policy override selected by trusted application code.

    Returns:
        Complete authorization decision with stable reason codes.
    """
    selected_policy = policy or safety_policy_for_manifest(manifest)
    requested = set(manifest.capabilities)
    reasons = _contract_reasons(manifest, selected_policy, requested)
    reasons.extend(_limit_reasons(manifest.limits, selected_policy.ceilings))
    reasons.extend(_approval_reasons(manifest, approval, requested))
    granted = tuple(sorted(requested & selected_policy.capabilities, key=lambda item: item.value))
    return AuthorizationDecision(not reasons, tuple(reasons), granted)


def _contract_reasons(
    manifest: RunManifest,
    policy: SafetyPolicy,
    requested: set[Capability],
) -> list[str]:
    reasons: list[str] = []
    if manifest.profile is not policy.profile:
        reasons.append("profile_denied")
    if manifest.adapter != policy.adapter:
        reasons.append("adapter_denied")
    if manifest.decision_provider != policy.decision_provider:
        reasons.append("decision_provider_denied")
    if manifest.policy != policy.policy:
        reasons.append("memory_policy_denied")
    if not requested <= policy.capabilities:
        reasons.append("capability_denied")
    if not policy.capabilities <= requested:
        reasons.append("required_capability_missing")
    return reasons


def _limit_reasons(requested: ExecutionLimits, ceilings: ExecutionLimits) -> list[str]:
    fields = (
        "episodes",
        "retrieval_calls",
        "logical_steps",
        "input_bytes",
        "memory_records",
        "artifact_bytes",
    )
    return [
        f"limit_exceeded:{name}"
        for name in fields
        if getattr(requested, name) > getattr(ceilings, name)
    ]


def _approval_reasons(
    manifest: RunManifest,
    approval: ApprovalRecord | None,
    requested: set[Capability],
) -> list[str]:
    if approval is None:
        return ["approval_missing"]
    reasons: list[str] = []
    if approval.manifest_sha256 != manifest.digest:
        reasons.append("approval_manifest_mismatch")
    if set(approval.capabilities) != requested:
        reasons.append("approval_scope_mismatch")
    return reasons


def resolve_existing_path(root: Path, relative_path: str) -> Path:
    """Resolve an existing file beneath an operator-controlled root.

    Args:
        root: Trusted scenario root.
        relative_path: Manifest-supplied POSIX path beneath the root.

    Returns:
        Resolved existing path.

    Raises:
        PathBoundaryError: If the root or candidate is invalid or escapes the root.
    """
    try:
        resolved_root = root.resolve(strict=True)
        candidate = (resolved_root / Path(*relative_path.split("/"))).resolve(strict=True)
        candidate.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise PathBoundaryError("scenario path must resolve beneath the scenario root") from exc
    if not candidate.is_file():
        raise PathBoundaryError("scenario path must name a regular file")
    return candidate


def resolve_artifact_root(root: Path) -> Path:
    """Resolve or create the operator-selected artifact root.

    Args:
        root: Artifact root selected outside the run manifest.

    Returns:
        Resolved directory path.

    Raises:
        PathBoundaryError: If the root cannot be created or is not a directory.
    """
    try:
        root.mkdir(parents=True, exist_ok=True)
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise PathBoundaryError("artifact root cannot be created") from exc
    if not resolved.is_dir():
        raise PathBoundaryError("artifact root must be a directory")
    return resolved
