"""Verified evidence inspection, comparison, and idempotent recovery."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from risi.artifacts import (
    ArtifactError,
    BundleVerification,
    InventoryEntry,
    load_json_artifact,
    verify_evidence_bundle,
)
from risi.budget import BudgetResource, ResourceUse
from risi.canonical import JsonValue, canonical_sha256, normalize_json_value
from risi.operator.models import CommandResult, ResultStatus, RunManifest

_MANIFEST_FIELDS = {
    "schema_version",
    "run_id",
    "profile",
    "scenario_path",
    "scenario_sha256",
    "seed",
    "adapter",
    "decision_provider",
    "policy",
    "capabilities",
    "limits",
}
_EXECUTION_COMMON_FIELDS = {
    "schema_version",
    "run_id",
    "scenario_id",
    "manifest_sha256",
    "episode_id",
    "policy",
    "status",
    "initial_state_hash",
    "event_count",
    "resource_use",
}
_PURE_READ_FIELDS = _EXECUTION_COMMON_FIELDS | {
    "safe",
    "reason_code",
    "final_state_hash",
}
_CRAF_FIELDS = _EXECUTION_COMMON_FIELDS | {"comparison_result", "arms"}
_RISI_C_FIELDS = _EXECUTION_COMMON_FIELDS | {"comparison_result", "pairs"}


def _object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{field_name} must be an object")
    return cast(dict[str, Any], value)


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ArtifactError(f"{field_name} must be a string")
    return value


def _integer(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArtifactError(f"{field_name} must be an integer")
    return value


def _boolean(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ArtifactError(f"{field_name} must be a boolean")
    return value


def _array(value: object, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ArtifactError(f"{field_name} must be an array")
    return cast(list[Any], value)


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    """Contain the closed experimental result anchor exposed by inspection."""

    status: str
    kind: str
    value: str
    reason_code: str | None

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed result representation."""
        return {
            "status": self.status,
            "kind": self.kind,
            "value": self.value,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    """Summarize a complete bundle only after integrity verification."""

    run_id: str
    manifest_sha256: str
    scenario: str
    policy: str
    result: EvidenceResult
    resource_use: ResourceUse
    inventory_sha256: str
    bundle_hash: str
    inventoried_paths: tuple[str, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed machine-readable inspection summary."""
        return {
            "run_id": self.run_id,
            "manifest_sha256": self.manifest_sha256,
            "scenario": self.scenario,
            "policy": self.policy,
            "result": self.result.to_json(),
            "resource_use": self.resource_use.to_json(),
            "inventory_sha256": self.inventory_sha256,
            "bundle_hash": self.bundle_hash,
            "inventoried_paths": list(self.inventoried_paths),
        }


class DifferenceScope(StrEnum):
    """Closed comparison-difference categories."""

    EVIDENCE_PATH = "evidence_path"
    SEMANTIC_ANCHOR = "semantic_anchor"


class DifferenceKind(StrEnum):
    """Closed comparison-difference reasons."""

    DIFFERENT = "different"
    MISSING_FROM_A = "missing_from_a"
    MISSING_FROM_B = "missing_from_b"


@dataclass(frozen=True, slots=True)
class EvidenceDifference:
    """Identify one stable path or semantic-anchor difference."""

    scope: DifferenceScope
    path: str
    kind: DifferenceKind

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed difference representation."""
        return {"scope": self.scope.value, "path": self.path, "kind": self.kind.value}


@dataclass(frozen=True, slots=True)
class ComparisonAnchor:
    """Identify one verified bundle in comparison output."""

    run_id: str
    inventory_sha256: str
    bundle_hash: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the bundle comparison anchor."""
        return {
            "run_id": self.run_id,
            "inventory_sha256": self.inventory_sha256,
            "bundle_hash": self.bundle_hash,
        }


@dataclass(frozen=True, slots=True)
class BundleComparison:
    """Report exact bundle equality or stable closed differences."""

    equal: bool
    bundle_a: ComparisonAnchor
    bundle_b: ComparisonAnchor
    differences: tuple[EvidenceDifference, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed comparison representation."""
        return {
            "equal": self.equal,
            "bundle_a": self.bundle_a.to_json(),
            "bundle_b": self.bundle_b.to_json(),
            "differences": [difference.to_json() for difference in self.differences],
        }


@dataclass(frozen=True, slots=True)
class RecoveredResult:
    """Contain an idempotently recovered completed run."""

    result: CommandResult
    bundle_path: Path
    verification: BundleVerification
    summary: EvidenceSummary


@dataclass(frozen=True, slots=True)
class _ExecutionMaterial:
    run_id: str
    manifest_sha256: str
    scenario_id: str
    episode_id: str
    policy: str
    status: str
    result: EvidenceResult
    resource_use: ResourceUse
    event_count: int
    detail_name: str | None
    details: JsonValue


def _parse_execution(execution: dict[str, Any]) -> _ExecutionMaterial:
    policy = _string(execution.get("policy"), "execution.policy")
    if policy == "pure-read":
        expected_fields = _PURE_READ_FIELDS
        safe = _boolean(execution.get("safe"), "execution.safe")
        reason_code = _string(execution.get("reason_code"), "execution.reason_code")
        result = EvidenceResult(
            status=_string(execution.get("status"), "execution.status"),
            kind="decision",
            value="safe" if safe else "unsafe",
            reason_code=reason_code,
        )
        detail_name = None
        details: JsonValue = None
    elif policy == "craf-reference":
        expected_fields = _CRAF_FIELDS
        comparison = _string(execution.get("comparison_result"), "execution.comparison_result")
        result = EvidenceResult(
            status=_string(execution.get("status"), "execution.status"),
            kind="comparison",
            value=comparison,
            reason_code=None,
        )
        detail_name = "arms"
        details = normalize_json_value(_array(execution.get("arms"), "execution.arms"))
    elif policy == "risi-c-reference":
        expected_fields = _RISI_C_FIELDS
        comparison = _string(execution.get("comparison_result"), "execution.comparison_result")
        result = EvidenceResult(
            status=_string(execution.get("status"), "execution.status"),
            kind="comparison",
            value=comparison,
            reason_code=None,
        )
        detail_name = "pairs"
        details = normalize_json_value(_array(execution.get("pairs"), "execution.pairs"))
    else:
        raise ArtifactError("execution.policy is not a registered evidence policy")
    if set(execution) != expected_fields:
        raise ArtifactError("execution evidence has an invalid field set")
    if execution.get("schema_version") != 1:
        raise ArtifactError("execution schema_version is invalid")
    status = _string(execution.get("status"), "execution.status")
    if status != "succeeded":
        raise ArtifactError("completed evidence must record succeeded execution")
    try:
        resource_use = ResourceUse.from_json(execution.get("resource_use"))
    except (TypeError, ValueError) as exc:
        raise ArtifactError(str(exc)) from exc
    event_count = _integer(execution.get("event_count"), "execution.event_count")
    if event_count < 0:
        raise ArtifactError("execution.event_count must be nonnegative")
    return _ExecutionMaterial(
        run_id=_string(execution.get("run_id"), "execution.run_id"),
        manifest_sha256=_string(execution.get("manifest_sha256"), "execution.manifest_sha256"),
        scenario_id=_string(execution.get("scenario_id"), "execution.scenario_id"),
        episode_id=_string(execution.get("episode_id"), "execution.episode_id"),
        policy=policy,
        status=status,
        result=result,
        resource_use=resource_use,
        event_count=event_count,
        detail_name=detail_name,
        details=details,
    )


def _inspect_verified(bundle_path: Path, verification: BundleVerification) -> EvidenceSummary:
    manifest = load_json_artifact(bundle_path, "manifest.json")
    execution = load_json_artifact(bundle_path, "execution.json")
    target = load_json_artifact(bundle_path, "target-scenario.json")
    if set(manifest) != _MANIFEST_FIELDS or manifest.get("schema_version") != 1:
        raise ArtifactError("manifest evidence has an invalid field set")
    parsed = _parse_execution(execution)
    limits = _object(manifest.get("limits"), "manifest.limits")
    if set(limits) != {resource.value for resource in BudgetResource}:
        raise ArtifactError("manifest.limits has an invalid field set")
    for resource in BudgetResource:
        approved = _integer(limits.get(resource.value), f"manifest.limits.{resource.value}")
        if getattr(parsed.resource_use, resource.value).approved != approved:
            raise ArtifactError("resource_use does not match the approved manifest limits")
    if parsed.resource_use.artifact_bytes.consumed != verification.total_bytes:
        raise ArtifactError("resource_use artifact_bytes does not match the verified bundle size")
    manifest_digest = canonical_sha256(manifest)
    manifest_run_id = _string(manifest.get("run_id"), "manifest.run_id")
    manifest_policy = _string(manifest.get("policy"), "manifest.policy")
    target_scenario = _string(target.get("scenario_id"), "target-scenario.scenario_id")
    if not (
        verification.run_id == manifest_run_id == parsed.run_id
        and manifest_digest == parsed.manifest_sha256
        and manifest_policy == parsed.policy
        and target_scenario == parsed.scenario_id
    ):
        raise ArtifactError("bundle semantic anchors are inconsistent")
    paths = tuple(sorted(entry.path for entry in verification.entries))
    return EvidenceSummary(
        run_id=parsed.run_id,
        manifest_sha256=manifest_digest,
        scenario=parsed.scenario_id,
        policy=parsed.policy,
        result=parsed.result,
        resource_use=parsed.resource_use,
        inventory_sha256=verification.inventory_sha256,
        bundle_hash=verification.bundle_hash,
        inventoried_paths=paths,
    )


def inspect_bundle(path: Path) -> EvidenceSummary:
    """Verify a complete bundle and return its closed evidence summary.

    Args:
        path: Completed evidence-bundle directory.

    Returns:
        Verified run identity, semantic anchors, resource use, and inventory paths.

    Raises:
        ArtifactError: If integrity or closed semantic anchors are invalid.
    """
    verification = verify_evidence_bundle(path)
    return _inspect_verified(path, verification)


def _entry_differences(
    entries_a: tuple[InventoryEntry, ...],
    entries_b: tuple[InventoryEntry, ...],
) -> list[EvidenceDifference]:
    by_path_a = {entry.path: entry for entry in entries_a}
    by_path_b = {entry.path: entry for entry in entries_b}
    differences: list[EvidenceDifference] = []
    for path in sorted(set(by_path_a) | set(by_path_b)):
        if path not in by_path_a:
            kind = DifferenceKind.MISSING_FROM_A
        elif path not in by_path_b:
            kind = DifferenceKind.MISSING_FROM_B
        elif by_path_a[path] != by_path_b[path]:
            kind = DifferenceKind.DIFFERENT
        else:
            continue
        differences.append(EvidenceDifference(DifferenceScope.EVIDENCE_PATH, path, kind))
    return differences


def _semantic_anchors(summary: EvidenceSummary) -> tuple[tuple[str, JsonValue], ...]:
    return (
        ("/run_id", summary.run_id),
        ("/manifest_sha256", summary.manifest_sha256),
        ("/scenario", summary.scenario),
        ("/policy", summary.policy),
        ("/result", summary.result.to_json()),
        ("/resource_use", summary.resource_use.to_json()),
        ("/inventory_sha256", summary.inventory_sha256),
        ("/bundle_hash", summary.bundle_hash),
    )


def compare_bundles(path_a: Path, path_b: Path) -> BundleComparison:
    """Verify and compare two completed evidence bundles.

    Args:
        path_a: First completed evidence-bundle directory.
        path_b: Second completed evidence-bundle directory.

    Returns:
        Exact equality or stable differing evidence paths and semantic anchors.

    Raises:
        ArtifactError: If either bundle fails integrity or semantic-anchor validation.
    """
    verification_a = verify_evidence_bundle(path_a)
    verification_b = verify_evidence_bundle(path_b)
    summary_a = _inspect_verified(path_a, verification_a)
    summary_b = _inspect_verified(path_b, verification_b)
    differences = _entry_differences(verification_a.entries, verification_b.entries)
    anchors_b = dict(_semantic_anchors(summary_b))
    for path, value_a in _semantic_anchors(summary_a):
        if value_a != anchors_b[path]:
            differences.append(
                EvidenceDifference(
                    DifferenceScope.SEMANTIC_ANCHOR,
                    path,
                    DifferenceKind.DIFFERENT,
                )
            )
    differences.sort(
        key=lambda item: (
            0 if item.scope is DifferenceScope.EVIDENCE_PATH else 1,
            item.path,
        )
    )
    exact = (
        verification_a.inventory_sha256 == verification_b.inventory_sha256
        and verification_a.bundle_hash == verification_b.bundle_hash
    )
    if exact and differences:
        raise ArtifactError("equal bundle digests have inconsistent comparison anchors")
    return BundleComparison(
        equal=exact,
        bundle_a=ComparisonAnchor(
            summary_a.run_id,
            summary_a.inventory_sha256,
            summary_a.bundle_hash,
        ),
        bundle_b=ComparisonAnchor(
            summary_b.run_id,
            summary_b.inventory_sha256,
            summary_b.bundle_hash,
        ),
        differences=tuple(differences),
    )


def command_result_from_execution(
    execution: dict[str, Any],
    bundle_path: Path,
    verification: BundleVerification,
    *,
    reused: bool,
) -> CommandResult:
    """Build the stable run envelope from closed execution evidence.

    Args:
        execution: Validated execution summary retained in the bundle.
        bundle_path: Completed bundle path.
        verification: Integrity anchor for the completed bundle.
        reused: Whether this result was recovered instead of re-executed.

    Returns:
        Stable operator run result.
    """
    parsed = _parse_execution(execution)
    data: dict[str, JsonValue] = {
        "scenario_id": parsed.scenario_id,
        "episode_id": parsed.episode_id,
        "bundle_path": str(bundle_path),
        "inventory_sha256": verification.inventory_sha256,
        "bundle_hash": verification.bundle_hash,
        "event_count": parsed.event_count,
        "resource_use": parsed.resource_use.to_json(),
        "reused": reused,
    }
    if parsed.result.kind == "decision":
        data["safe"] = parsed.result.value == "safe"
        data["reason_code"] = parsed.result.reason_code
    else:
        data["comparison_result"] = parsed.result.value
        if parsed.detail_name is None:
            raise ArtifactError("comparison execution is missing its detail anchor")
        data[parsed.detail_name] = parsed.details
    return CommandResult(
        command="run",
        status=ResultStatus.OK,
        run_id=parsed.run_id,
        data=data,
    )


def recover_existing_result(artifact_root: Path, manifest: RunManifest) -> RecoveredResult | None:
    """Recover an immutable completed run or signal that execution may begin.

    Args:
        artifact_root: Operator-controlled artifact root.
        manifest: Authorized and semantically validated run manifest.

    Returns:
        Existing verified result with ``reused`` set, or ``None`` when no final bundle exists.

    Raises:
        ArtifactError: If an existing final path is incomplete, tampered, or bound differently.
    """
    candidate = artifact_root / manifest.run_id
    if not candidate.exists():
        return None
    try:
        resolved_root = artifact_root.resolve(strict=True)
        bundle_path = candidate.resolve(strict=True)
        bundle_path.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ArtifactError("existing evidence path cannot be resolved") from exc
    if not resolved_root.is_dir() or candidate.is_symlink():
        raise ArtifactError("existing evidence path must be a contained non-symlink directory")
    verification = verify_evidence_bundle(bundle_path)
    summary = _inspect_verified(bundle_path, verification)
    if summary.run_id != manifest.run_id or summary.manifest_sha256 != manifest.digest:
        raise ArtifactError("existing evidence does not match the authorized manifest")
    execution = load_json_artifact(bundle_path, "execution.json")
    result = command_result_from_execution(
        execution,
        bundle_path,
        verification,
        reused=True,
    )
    return RecoveredResult(result, bundle_path, verification, summary)


def inspect_campaign_bundle(path: Path) -> dict[str, JsonValue]:
    """Verify and summarize an isolated-target campaign bundle."""
    verification = verify_evidence_bundle(path)
    manifest = load_json_artifact(path, "campaign-manifest.json")
    result = load_json_artifact(path, "result.json")
    if manifest.get("campaign_id") != verification.run_id:
        raise ArtifactError("campaign manifest does not match the bundle identity")
    if result.get("campaign_id") != verification.run_id:
        raise ArtifactError("campaign result does not match the bundle identity")
    return {
        "campaign_id": verification.run_id,
        "status": cast(JsonValue, result.get("status")),
        "world_count": cast(JsonValue, result.get("world_count")),
        "observation_count": cast(JsonValue, result.get("observation_count")),
        "request_count": cast(JsonValue, result.get("request_count")),
        "inventory_sha256": verification.inventory_sha256,
        "bundle_hash": verification.bundle_hash,
    }


def compare_campaign_bundles(path_a: Path, path_b: Path) -> dict[str, JsonValue]:
    """Verify and compare two campaign bundle inventories without target access."""
    first = inspect_campaign_bundle(path_a)
    second = inspect_campaign_bundle(path_b)
    fields = ("status", "world_count", "observation_count", "request_count", "bundle_hash")
    differences: list[JsonValue] = [
        {"field": field, "first": first[field], "second": second[field]}
        for field in fields
        if first[field] != second[field]
    ]
    return {"equal": not differences, "differences": differences}
