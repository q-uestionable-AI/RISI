"""Guarded lifecycle and evidence services for isolated-target campaigns."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

from risi.adapters.external import (
    ExternalKnowledgeAdapter,
    ExternalTargetManifest,
    load_external_target_manifest,
)
from risi.artifacts import BundleVerification, create_evidence_bundle, json_bytes, json_lines_bytes
from risi.canonical import (
    JsonObject,
    JsonValue,
    canonical_sha256,
    freeze_json_object,
    normalize_json_object,
)
from risi.operator.models import Capability, OperatorInputError
from risi.operator.safety import ISOLATED_DIFY_CAPABILITIES, AuthorizationDecision
from risi.statistics import e1_campaign_geometry
from risi.transport import CancellationToken, TransportError

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")

CAMPAIGN_CAPABILITIES = ISOLATED_DIFY_CAPABILITIES
E2_DRY_RUN_SCENARIOS = 10
E2_STABILITY_RECREATIONS = 3
E2_STABILITY_QUERIES = 3
E2_ATTEMPT_SECONDS = 2 * 60 * 60
E1_PROJECTED_SECONDS = 6 * 60 * 60
E2_DOCUMENTS_PER_SCENARIO = 56
E2_RETRIEVALS_PER_SCENARIO = 22


class CampaignPurpose(StrEnum):
    """Separate E2 validation authority from E3 campaign authority."""

    E2_VALIDATION = "e2-validation"
    E3_CAMPAIGN = "e3-campaign"


class CampaignPhase(StrEnum):
    """Closed lifecycle phases retained outside target-visible state."""

    PREPARED = "prepared"
    PREFLIGHT_PASSED = "preflight-passed"
    RUNNING = "running"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class CampaignManifest:
    """Bind one campaign to exact target, input, geometry, and evidence identities."""

    schema_version: int
    campaign_id: str
    target_manifest_sha256: str
    input_inventory_sha256: str
    world_count: int
    observations_per_world: int
    total_observations: int
    top_k: int
    retrieval_mode: str
    evidence_relative_path: str
    expires_on: str
    validation_only: bool
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate immutable campaign constraints."""
        if self.schema_version != 1:
            raise OperatorInputError("campaign manifest schema_version must be 1")
        if _IDENTIFIER.fullmatch(self.campaign_id) is None:
            raise OperatorInputError("campaign_id must be a lowercase registered identifier")
        for name in ("target_manifest_sha256", "input_inventory_sha256"):
            if _DIGEST.fullmatch(getattr(self, name)) is None:
                raise OperatorInputError(f"{name} must be a lowercase SHA-256 digest")
        if self.world_count <= 0 or self.observations_per_world <= 0:
            raise OperatorInputError("campaign geometry must be positive")
        if self.total_observations != self.world_count * self.observations_per_world:
            raise OperatorInputError("campaign total_observations does not match its geometry")
        if self.top_k != 5 or self.retrieval_mode != "semantic-vector":
            raise OperatorInputError("campaign retrieval must be semantic-vector top_k=5")
        evidence_path = Path(self.evidence_relative_path)
        if (
            evidence_path.is_absolute()
            or ".." in evidence_path.parts
            or "\\" in self.evidence_relative_path
        ):
            raise OperatorInputError("evidence_relative_path must be a contained POSIX path")
        try:
            date.fromisoformat(self.expires_on)
        except ValueError as exc:
            raise OperatorInputError("expires_on must be an ISO date") from exc
        object.__setattr__(self, "metadata", freeze_json_object(self.metadata))

    @property
    def digest(self) -> str:
        """Return the canonical manifest digest."""
        return canonical_sha256(self.to_json())

    def to_json(self) -> dict[str, JsonValue]:
        """Return the campaign-manifest representation."""
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "target_manifest_sha256": self.target_manifest_sha256,
            "input_inventory_sha256": self.input_inventory_sha256,
            "world_count": self.world_count,
            "observations_per_world": self.observations_per_world,
            "total_observations": self.total_observations,
            "top_k": self.top_k,
            "retrieval_mode": self.retrieval_mode,
            "evidence_relative_path": self.evidence_relative_path,
            "expires_on": self.expires_on,
            "validation_only": self.validation_only,
            "metadata": normalize_json_object(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class CampaignApproval:
    """Bind a human decision to exact campaign and target manifests."""

    schema_version: int
    decision_id: str
    status: str
    purpose: CampaignPurpose
    campaign_manifest_sha256: str
    target_manifest_sha256: str
    input_inventory_sha256: str
    approved_by: str
    capabilities: tuple[Capability, ...]
    expires_on: str
    max_attempts: int
    note: str = ""

    def __post_init__(self) -> None:
        """Validate decision identity, binding, expiry, and exact capability scope."""
        if self.schema_version != 1:
            raise OperatorInputError("campaign approval schema_version must be 1")
        if (
            not self.decision_id.strip()
            or self.status != "accepted"
            or not self.approved_by.strip()
        ):
            raise OperatorInputError("campaign approval identity or status is invalid")
        for name in (
            "campaign_manifest_sha256",
            "target_manifest_sha256",
            "input_inventory_sha256",
        ):
            if _DIGEST.fullmatch(getattr(self, name)) is None:
                raise OperatorInputError(f"{name} must be a lowercase SHA-256 digest")
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        if len(self.capabilities) != len(set(self.capabilities)):
            raise OperatorInputError("campaign approval capabilities must be unique")
        try:
            date.fromisoformat(self.expires_on)
        except ValueError as exc:
            raise OperatorInputError("approval expires_on must be an ISO date") from exc
        expected_attempts = 3 if self.purpose is CampaignPurpose.E2_VALIDATION else 1
        if self.max_attempts != expected_attempts:
            raise OperatorInputError("approval max_attempts does not match its purpose")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the campaign-approval representation."""
        return {
            "schema_version": self.schema_version,
            "decision_id": self.decision_id,
            "status": self.status,
            "purpose": self.purpose.value,
            "campaign_manifest_sha256": self.campaign_manifest_sha256,
            "target_manifest_sha256": self.target_manifest_sha256,
            "input_inventory_sha256": self.input_inventory_sha256,
            "approved_by": self.approved_by,
            "capabilities": [item.value for item in self.capabilities],
            "expires_on": self.expires_on,
            "max_attempts": self.max_attempts,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class CampaignMemory:
    """Contain one target-visible synthetic document."""

    memory_id: str
    content: str

    def __post_init__(self) -> None:
        """Validate bounded synthetic memory content."""
        if (
            _IDENTIFIER.fullmatch(self.memory_id) is None
            or not self.content.strip()
            or "␞" in self.content
        ):
            raise OperatorInputError("campaign memory is invalid")


@dataclass(frozen=True, slots=True)
class CampaignWorld:
    """Contain one frozen target-visible scenario world."""

    world_id: str
    source_memories: tuple[CampaignMemory, ...]
    benign_pool: tuple[CampaignMemory, ...]
    targeted_pool: tuple[CampaignMemory, ...]
    target_query: str
    non_target_query: str

    def __post_init__(self) -> None:
        """Validate the fixed two-source and 25-per-condition world shape."""
        object.__setattr__(self, "source_memories", tuple(self.source_memories))
        object.__setattr__(self, "benign_pool", tuple(self.benign_pool))
        object.__setattr__(self, "targeted_pool", tuple(self.targeted_pool))
        if _IDENTIFIER.fullmatch(self.world_id) is None:
            raise OperatorInputError("world_id is invalid")
        if (
            len(self.source_memories) != 2
            or len(self.benign_pool) != 25
            or len(self.targeted_pool) != 25
        ):
            raise OperatorInputError("campaign world does not have the frozen source/pool shape")
        memories = self.source_memories + self.benign_pool + self.targeted_pool
        if len({memory.memory_id for memory in memories}) != len(memories):
            raise OperatorInputError("campaign memory IDs must be unique within a world")
        if not self.target_query.strip() or not self.non_target_query.strip():
            raise OperatorInputError("campaign queries must not be empty")


@dataclass(frozen=True, slots=True)
class EvaluatorOracle:
    """Contain evaluator-only protected-memory identities for one world."""

    world_id: str
    target_memory_id: str
    non_target_memory_id: str


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """Retain immutable preflight decisions without granting execution authority."""

    schema_version: int
    campaign_id: str
    target_manifest_sha256: str
    campaign_manifest_sha256: str
    input_inventory_sha256: str
    passed: bool
    checks: JsonObject
    attempt: int

    def to_json(self) -> dict[str, JsonValue]:
        """Return the preflight-result representation."""
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "target_manifest_sha256": self.target_manifest_sha256,
            "campaign_manifest_sha256": self.campaign_manifest_sha256,
            "input_inventory_sha256": self.input_inventory_sha256,
            "passed": self.passed,
            "checks": normalize_json_object(self.checks),
            "attempt": self.attempt,
        }


@dataclass(frozen=True, slots=True)
class CampaignCheckpoint:
    """Record durable campaign lifecycle progress."""

    schema_version: int
    campaign_id: str
    phase: CampaignPhase
    next_world_index: int
    observation_count: int
    request_count: int
    manifest_sha256: str
    message: str = ""

    def to_json(self) -> dict[str, JsonValue]:
        """Return the checkpoint representation."""
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "phase": self.phase.value,
            "next_world_index": self.next_world_index,
            "observation_count": self.observation_count,
            "request_count": self.request_count,
            "manifest_sha256": self.manifest_sha256,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class Deviation:
    """Record one retained, non-overwriting campaign deviation."""

    schema_version: int
    campaign_id: str
    phase: str
    code: str
    message: str
    request_count: int
    observation_count: int

    def to_json(self) -> dict[str, JsonValue]:
        """Return a credential-free deviation record."""
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "phase": self.phase,
            "code": self.code,
            "message": self.message,
            "request_count": self.request_count,
            "observation_count": self.observation_count,
        }


def _read_object(path: Path, contract: str) -> dict[str, Any]:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError(f"cannot read {contract}: {exc}") from exc
    if not isinstance(value, dict):
        raise OperatorInputError(f"{contract} must be a JSON object")
    return cast(dict[str, Any], value)


def _exact(value: dict[str, Any], fields: set[str], contract: str) -> None:
    if set(value) != fields:
        raise OperatorInputError(f"{contract} has an invalid field set")


def load_campaign_manifest(path: Path) -> CampaignManifest:
    """Strictly load a campaign manifest."""
    value = _read_object(path, "campaign manifest")
    fields = {
        "schema_version",
        "campaign_id",
        "target_manifest_sha256",
        "input_inventory_sha256",
        "world_count",
        "observations_per_world",
        "total_observations",
        "top_k",
        "retrieval_mode",
        "evidence_relative_path",
        "expires_on",
        "validation_only",
        "metadata",
    }
    _exact(value, fields, "campaign manifest")
    return CampaignManifest(**value)


def load_campaign_approval(path: Path) -> CampaignApproval:
    """Strictly load a campaign approval."""
    value = _read_object(path, "campaign approval")
    fields = {
        "schema_version",
        "decision_id",
        "status",
        "purpose",
        "campaign_manifest_sha256",
        "target_manifest_sha256",
        "input_inventory_sha256",
        "approved_by",
        "capabilities",
        "expires_on",
        "max_attempts",
        "note",
    }
    _exact(value, fields, "campaign approval")
    try:
        capabilities = tuple(Capability(item) for item in value["capabilities"])
        purpose = CampaignPurpose(value["purpose"])
    except (TypeError, ValueError) as exc:
        raise OperatorInputError("campaign approval contains an unknown enum value") from exc
    return CampaignApproval(
        schema_version=value["schema_version"],
        decision_id=value["decision_id"],
        status=value["status"],
        purpose=purpose,
        campaign_manifest_sha256=value["campaign_manifest_sha256"],
        target_manifest_sha256=value["target_manifest_sha256"],
        input_inventory_sha256=value["input_inventory_sha256"],
        approved_by=value["approved_by"],
        capabilities=capabilities,
        expires_on=value["expires_on"],
        max_attempts=value["max_attempts"],
        note=value["note"],
    )


def _approval_reason_codes(
    manifest: CampaignManifest,
    target: ExternalTargetManifest,
    approval: CampaignApproval,
    on_date: date | None,
) -> tuple[str, ...]:
    """Return deterministic reason codes for one present campaign approval."""
    reasons: list[str] = []
    if approval.campaign_manifest_sha256 != manifest.digest:
        reasons.append("approval_manifest_mismatch")
    if approval.target_manifest_sha256 != target.digest:
        reasons.append("approval_target_mismatch")
    if approval.input_inventory_sha256 != manifest.input_inventory_sha256:
        reasons.append("approval_input_mismatch")
    if set(approval.capabilities) != CAMPAIGN_CAPABILITIES:
        reasons.append("approval_scope_mismatch")
    current_date = on_date or datetime.now(UTC).date()
    if current_date > date.fromisoformat(approval.expires_on) or current_date > date.fromisoformat(
        manifest.expires_on
    ):
        reasons.append("approval_expired")
    if manifest.validation_only:
        if (
            approval.purpose is not CampaignPurpose.E2_VALIDATION
            or not approval.decision_id.startswith("E2-")
        ):
            reasons.append("e2_validation_approval_required")
    elif approval.purpose is not CampaignPurpose.E3_CAMPAIGN or not approval.decision_id.startswith(
        "E3-"
    ):
        reasons.append("e3_approval_required")
    return tuple(reasons)


def authorize_campaign(
    manifest: CampaignManifest,
    target: ExternalTargetManifest,
    approval: CampaignApproval | None,
    *,
    on_date: date | None = None,
) -> AuthorizationDecision:
    """Authorize an exact campaign under the model-independent safety kernel."""
    reasons: list[str] = []
    requested = CAMPAIGN_CAPABILITIES
    if target.digest != manifest.target_manifest_sha256:
        reasons.append("target_manifest_mismatch")
    if approval is None:
        reasons.append("approval_missing")
        granted: tuple[Capability, ...] = ()
    else:
        reasons.extend(_approval_reason_codes(manifest, target, approval, on_date))
        granted = tuple(sorted(requested & set(approval.capabilities), key=lambda item: item.value))
    return AuthorizationDecision(not reasons, tuple(reasons), granted)


def validate_e1_geometry(manifest: CampaignManifest) -> None:
    """Reject drift from the accepted 330-world E1 geometry."""
    geometry = e1_campaign_geometry()
    if manifest.validation_only:
        return
    if (
        manifest.world_count != geometry.world_count
        or manifest.observations_per_world != geometry.observations_per_world
        or manifest.total_observations != geometry.total_observations
    ):
        raise OperatorInputError("E1 campaign geometry differs from the accepted design")


def _atomic_write(path: Path, content: bytes, *, overwrite: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise OperatorInputError(f"retained path already exists: {path.name}")
    with NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
    try:
        temporary_path.replace(path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


def prepare_campaign(
    workspace: Path,
    manifest: CampaignManifest,
    target: ExternalTargetManifest,
    approval: CampaignApproval | None,
) -> CampaignCheckpoint:
    """Validate authority and atomically retain a prepared lifecycle checkpoint."""
    decision = authorize_campaign(manifest, target, approval)
    if not decision.allowed:
        raise PermissionError(",".join(decision.reason_codes))
    validate_e1_geometry(manifest)
    checkpoint = CampaignCheckpoint(
        1, manifest.campaign_id, CampaignPhase.PREPARED, 0, 0, 0, manifest.digest
    )
    _atomic_write(
        workspace / f"{manifest.campaign_id}.checkpoint.json",
        json_bytes(checkpoint.to_json()),
        overwrite=False,
    )
    return checkpoint


def _require_empty_owner_inventory(
    adapter: ExternalKnowledgeAdapter, cancellation: CancellationToken
) -> None:
    """Require the dedicated owner to see no retained or unrelated knowledge bases."""
    if adapter.list_knowledge_bases(cancellation):
        raise TransportError(
            "owner_isolation_failed", "dedicated target owner sees a retained knowledge base"
        )


def _ingest_validation_document(
    adapter: ExternalKnowledgeAdapter,
    dataset_id: str,
    name: str,
    content: str,
    cancellation: CancellationToken,
) -> str:
    """Ingest one neutral validation document and verify the one-chunk contract."""
    document_id, batch_id = adapter.create_document(dataset_id, name, content, cancellation)
    adapter.wait_for_indexing(dataset_id, batch_id, cancellation)
    segments = adapter.inspect_segments(dataset_id, document_id, cancellation)
    if len(segments) != 1 or segments[0].get("content") != content:
        raise TransportError(
            "reset_contract_failed", "validation document differs from its canonical source"
        )
    return document_id


def _run_stability_validation(
    adapter: ExternalKnowledgeAdapter, cancellation: CancellationToken
) -> None:
    """Verify three clean recreations and three stable repeated queries per recreation."""
    reset_shape: tuple[object, ...] | None = None
    for recreation in range(1, E2_STABILITY_RECREATIONS + 1):
        dataset_id = adapter.create_knowledge_base(f"risi-e2-stability-{recreation}", cancellation)
        try:
            content = "Synthetic E2 stability probe. Neutral control token amber-circuit."
            document_id = _ingest_validation_document(
                adapter, dataset_id, f"stability-{recreation}", content, cancellation
            )
            results = tuple(
                adapter.retrieve(dataset_id, "Locate the neutral control token.", cancellation)
                for _ in range(E2_STABILITY_QUERIES)
            )
            reference = results[0].hits
            if not reference:
                raise TransportError(
                    "stability_contract_failed", "stability retrieval returned no segments"
                )
            reference_ids = tuple(hit.segment_id for hit in reference)
            reference_scores = tuple(hit.score for hit in reference)
            for result in results[1:]:
                if tuple(hit.segment_id for hit in result.hits) != reference_ids:
                    raise TransportError(
                        "stability_contract_failed",
                        "repeated retrieval changed the ordered segment identity",
                    )
                scores = tuple(hit.score for hit in result.hits)
                if len(scores) != len(reference_scores) or any(
                    abs(actual - expected) > 1e-6
                    for actual, expected in zip(scores, reference_scores, strict=True)
                ):
                    raise TransportError(
                        "stability_contract_failed",
                        "repeated retrieval score exceeded the fixed tolerance",
                    )
            segments = adapter.inspect_segments(dataset_id, document_id, cancellation)
            current_shape = (
                len(segments),
                segments[0].get("content"),
                segments[0].get("enabled") is True,
            )
            if reset_shape is None:
                reset_shape = current_shape
            elif current_shape != reset_shape:
                raise TransportError(
                    "reset_contract_failed", "clean recreation changed the one-chunk inventory"
                )
        finally:
            if not cancellation.cancelled:
                adapter.delete_knowledge_base(dataset_id, cancellation)
        _require_empty_owner_inventory(adapter, cancellation)


def _run_throughput_scenario(
    adapter: ExternalKnowledgeAdapter,
    scenario: int,
    cancellation: CancellationToken,
) -> tuple[int, int]:
    """Run one outcome-free workload with the accepted E1 request geometry."""
    document_count = 0
    retrieval_count = 0
    conditions = (
        ("reference", 2, (2,)),
        ("sequence-a", 27, (7, 12, 17, 22, 27)),
        ("sequence-b", 27, (7, 12, 17, 22, 27)),
    )
    for condition, documents, checkpoints in conditions:
        dataset_id = adapter.create_knowledge_base(
            f"risi-e2-throughput-{scenario:02d}-{condition}", cancellation
        )
        try:
            for index in range(1, documents + 1):
                content = (
                    f"Synthetic E2 throughput probe {scenario:02d}, {condition}, document "
                    f"{index:02d}. Neutral token circuit-{scenario:02d}-{index:02d}."
                )
                _ingest_validation_document(
                    adapter,
                    dataset_id,
                    f"probe-{scenario:02d}-{condition}-{index:02d}",
                    content,
                    cancellation,
                )
                document_count += 1
                if index in checkpoints:
                    for query_kind in ("primary", "control"):
                        result = adapter.retrieve(
                            dataset_id,
                            f"Locate the {query_kind} neutral token for probe {scenario:02d}.",
                            cancellation,
                        )
                        if not result.hits:
                            raise TransportError(
                                "throughput_contract_failed",
                                "throughput retrieval returned no segments",
                            )
                        retrieval_count += 1
            adapter.inspect_knowledge_base(dataset_id, cancellation)
        finally:
            if not cancellation.cancelled:
                adapter.delete_knowledge_base(dataset_id, cancellation)
        _require_empty_owner_inventory(adapter, cancellation)
    return document_count, retrieval_count


def run_e2_target_validation(
    adapter: ExternalKnowledgeAdapter,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> JsonObject:
    """Run the accepted outcome-free reset, stability, and ten-scenario throughput preflight."""
    cancellation = CancellationToken()
    attempt_started = monotonic()
    _require_empty_owner_inventory(adapter, cancellation)
    health_before = adapter.read_health(cancellation)
    if health_before.get("status") != "healthy":
        raise TransportError("health_contract_failed", "target health is not healthy")
    _run_stability_validation(adapter, cancellation)
    throughput_started = monotonic()
    document_count = 0
    retrieval_count = 0
    for scenario in range(1, E2_DRY_RUN_SCENARIOS + 1):
        documents, retrievals = _run_throughput_scenario(adapter, scenario, cancellation)
        document_count += documents
        retrieval_count += retrievals
    throughput_elapsed = monotonic() - throughput_started
    health_after = adapter.read_health(cancellation)
    _require_empty_owner_inventory(adapter, cancellation)
    attempt_elapsed = monotonic() - attempt_started
    projected_seconds = throughput_elapsed * 330 / E2_DRY_RUN_SCENARIOS
    counts_match = (
        document_count == E2_DRY_RUN_SCENARIOS * E2_DOCUMENTS_PER_SCENARIO
        and retrieval_count == E2_DRY_RUN_SCENARIOS * E2_RETRIEVALS_PER_SCENARIO
    )
    validation_passed = (
        counts_match
        and health_after.get("status") == "healthy"
        and attempt_elapsed <= E2_ATTEMPT_SECONDS
        and projected_seconds <= E1_PROJECTED_SECONDS
    )
    return freeze_json_object(
        {
            "validation_passed": validation_passed,
            "targeted_outcomes_evaluated": False,
            "owner_inventory_empty_before_after": True,
            "health_before_after": health_after.get("status") == "healthy",
            "stability_recreations": E2_STABILITY_RECREATIONS,
            "stability_queries_per_recreation": E2_STABILITY_QUERIES,
            "ordered_segment_stability": True,
            "score_tolerance": 1e-6,
            "reset_inventory_equal": True,
            "dry_run_scenarios": E2_DRY_RUN_SCENARIOS,
            "dry_run_documents": document_count,
            "dry_run_retrievals": retrieval_count,
            "dry_run_counts_match": counts_match,
            "dry_run_elapsed_seconds": round(throughput_elapsed, 6),
            "projected_e1_seconds": round(projected_seconds, 6),
            "projection_within_six_hours": projected_seconds <= E1_PROJECTED_SECONDS,
            "attempt_elapsed_seconds": round(attempt_elapsed, 6),
            "attempt_within_two_hours": attempt_elapsed <= E2_ATTEMPT_SECONDS,
        }
    )


def campaign_preflight(
    manifest: CampaignManifest,
    target: ExternalTargetManifest,
    approval: CampaignApproval | None,
    adapter: ExternalKnowledgeAdapter,
    *,
    attempt: int,
    validation_runner: Callable[[ExternalKnowledgeAdapter], JsonObject] = run_e2_target_validation,
) -> PreflightResult:
    """Run the bounded application-level identity and health preflight once."""
    decision = authorize_campaign(manifest, target, approval)
    if not 1 <= attempt <= (approval.max_attempts if approval is not None else 1):
        raise OperatorInputError("preflight attempt is outside its approval ceiling")
    checks: dict[str, JsonValue] = {
        "authorization": decision.allowed,
        "geometry": manifest.validation_only
        or manifest.total_observations == e1_campaign_geometry().total_observations,
        "target_profile": target.profile.value == "isolated-dify-knowledge",
        "automatic_retry_count": target.automatic_retry_count,
        "request_timeout_seconds": target.request_timeout_seconds,
    }
    validation_geometry = (
        manifest.world_count == E2_DRY_RUN_SCENARIOS
        and manifest.observations_per_world == 1
        and manifest.total_observations == E2_DRY_RUN_SCENARIOS
    )
    checks["validation_geometry"] = not manifest.validation_only or validation_geometry
    if decision.allowed and checks["validation_geometry"] is True:
        try:
            if manifest.validation_only:
                checks.update(validation_runner(adapter))
            else:
                health = adapter.read_health(CancellationToken())
                checks["target_health"] = health.get("status") == "healthy"
                checks["validation_passed"] = checks["target_health"]
        except TransportError as exc:
            checks["validation_passed"] = False
            checks["failure_code"] = exc.code
    else:
        checks["validation_passed"] = False
    passed = (
        checks["authorization"] is True
        and checks["geometry"] is True
        and checks["target_profile"] is True
        and checks["automatic_retry_count"] == 0
        and checks["request_timeout_seconds"] == 10
        and checks["validation_geometry"] is True
        and checks["validation_passed"] is True
    )
    return PreflightResult(
        1,
        manifest.campaign_id,
        target.digest,
        manifest.digest,
        manifest.input_inventory_sha256,
        passed,
        checks,
        attempt,
    )


def _validated_observation_count(
    observations: list[dict[str, JsonValue]], manifest: CampaignManifest
) -> int:
    """Return the completed observation count or reject incomplete evidence."""
    observation_count = len(observations) * 2
    if observation_count != manifest.total_observations:
        raise OperatorInputError("completed observation count differs from the manifest")
    return observation_count


class CampaignExecutor:
    """Execute an E3-authorized campaign through one external adapter."""

    def __init__(
        self, adapter: ExternalKnowledgeAdapter, *, request_count: Callable[[], int]
    ) -> None:
        """Bind the executor to an adapter and its monotonic request counter."""
        self._adapter = adapter
        self._request_count = request_count

    def _ingest(
        self,
        dataset_id: str,
        memories: tuple[CampaignMemory, ...],
        token: CancellationToken,
    ) -> dict[str, str]:
        document_ids: dict[str, str] = {}
        for memory in memories:
            document_id, batch_id = self._adapter.create_document(
                dataset_id, memory.memory_id, memory.content, token
            )
            self._adapter.wait_for_indexing(dataset_id, batch_id, token)
            segments = self._adapter.inspect_segments(dataset_id, document_id, token)
            if segments[0].get("content") != memory.content:
                raise TransportError(
                    "source_mismatch", "stored chunk differs from canonical source"
                )
            document_ids[memory.memory_id] = document_id
        return document_ids

    def _observe(  # noqa: PLR0913 - observation context fields remain structurally separate
        self,
        world: CampaignWorld,
        oracle: EvaluatorOracle,
        dataset_id: str,
        condition: str,
        budget: int,
        document_ids: dict[str, str],
        token: CancellationToken,
    ) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
        observations: dict[str, JsonValue] = {
            "schema_version": 1,
            "world_id": world.world_id,
            "condition": condition,
            "budget": budget,
        }
        evaluations: dict[str, JsonValue] = {
            "schema_version": 1,
            "world_id": world.world_id,
            "condition": condition,
            "budget": budget,
        }
        for label, query, expected_memory in (
            ("target", world.target_query, oracle.target_memory_id),
            ("non_target", world.non_target_query, oracle.non_target_memory_id),
        ):
            result = self._adapter.retrieve(dataset_id, query, token)
            observations[label] = result.to_json()
            expected_document = document_ids[expected_memory]
            rank = next(
                (hit.rank for hit in result.hits if hit.document_id == expected_document), None
            )
            evaluations[label] = {"critical_recalled": rank is not None, "critical_rank": rank}
        return observations, evaluations

    def _run_world(
        self,
        world: CampaignWorld,
        oracle: EvaluatorOracle,
        token: CancellationToken,
    ) -> tuple[list[dict[str, JsonValue]], list[dict[str, JsonValue]]]:
        if oracle.world_id != world.world_id:
            raise OperatorInputError("oracle world does not match target-visible world")
        observations: list[dict[str, JsonValue]] = []
        evaluations: list[dict[str, JsonValue]] = []
        for condition, pool, checkpoints in (
            ("baseline", (), (0,)),
            ("benign", world.benign_pool, (5, 10, 15, 20, 25)),
            ("targeted", world.targeted_pool, (5, 10, 15, 20, 25)),
        ):
            dataset_id = self._adapter.create_knowledge_base(f"{world.world_id}-{condition}", token)
            try:
                documents = self._ingest(dataset_id, world.source_memories, token)
                previous = 0
                for budget in checkpoints:
                    additions = tuple(pool[previous:budget])
                    documents.update(self._ingest(dataset_id, additions, token))
                    observation, evaluation = self._observe(
                        world, oracle, dataset_id, condition, budget, documents, token
                    )
                    observations.append(observation)
                    evaluations.append(evaluation)
                    previous = budget
                self._adapter.inspect_knowledge_base(dataset_id, token)
            finally:
                if not token.cancelled:
                    self._adapter.delete_knowledge_base(dataset_id, token)
        return observations, evaluations

    def execute(  # noqa: PLR0913 - guarded inputs are independent authority boundaries
        self,
        artifact_root: Path,
        workspace: Path,
        manifest: CampaignManifest,
        target: ExternalTargetManifest,
        approval: CampaignApproval | None,
        worlds: tuple[CampaignWorld, ...],
        oracles: tuple[EvaluatorOracle, ...],
    ) -> BundleVerification:
        """Execute one immutable campaign attempt and finalize evidence atomically."""
        decision = authorize_campaign(manifest, target, approval)
        if not decision.allowed:
            raise PermissionError(",".join(decision.reason_codes))
        if manifest.validation_only:
            raise PermissionError("validation-only manifests cannot produce campaign outcomes")
        validate_e1_geometry(manifest)
        if len(worlds) != manifest.world_count or len(oracles) != manifest.world_count:
            raise OperatorInputError("input record counts do not match the campaign manifest")
        checkpoint_path = workspace / f"{manifest.campaign_id}.checkpoint.json"
        cancellation_path = workspace / f"{manifest.campaign_id}.cancel"
        deviation_path = workspace / f"{manifest.campaign_id}.deviation.json"
        token = CancellationToken()
        observations: list[dict[str, JsonValue]] = []
        evaluations: list[dict[str, JsonValue]] = []
        try:
            for index, (world, oracle) in enumerate(zip(worlds, oracles, strict=True)):
                if cancellation_path.exists():
                    token.cancel()
                    token.raise_if_cancelled()
                checkpoint = CampaignCheckpoint(
                    1,
                    manifest.campaign_id,
                    CampaignPhase.RUNNING,
                    index,
                    len(observations) * 2,
                    int(self._request_count()),
                    manifest.digest,
                )
                _atomic_write(checkpoint_path, json_bytes(checkpoint.to_json()))
                world_observations, world_evaluations = self._run_world(world, oracle, token)
                observations.extend(world_observations)
                evaluations.extend(world_evaluations)
            observation_count = _validated_observation_count(observations, manifest)
            files = {
                "campaign-manifest.json": json_bytes(manifest.to_json()),
                "target-manifest-digest.json": json_bytes(
                    {"target_manifest_sha256": target.digest}
                ),
                "observations.jsonl": json_lines_bytes(tuple(observations)),
                "evaluator-assessments.jsonl": json_lines_bytes(tuple(evaluations)),
                "result.json": json_bytes(
                    {
                        "schema_version": 1,
                        "campaign_id": manifest.campaign_id,
                        "status": "completed",
                        "world_count": len(worlds),
                        "observation_count": observation_count,
                        "request_count": int(self._request_count()),
                    }
                ),
            }
            verification = create_evidence_bundle(
                artifact_root,
                manifest.campaign_id,
                files,
                max_bytes=2_000_000_000,
            )
            completed = CampaignCheckpoint(
                1,
                manifest.campaign_id,
                CampaignPhase.COMPLETED,
                len(worlds),
                observation_count,
                int(self._request_count()),
                manifest.digest,
            )
            _atomic_write(checkpoint_path, json_bytes(completed.to_json()))
        except (TransportError, OperatorInputError, PermissionError) as exc:
            phase = (
                CampaignPhase.CANCELLED
                if isinstance(exc, TransportError) and exc.code == "cancelled"
                else CampaignPhase.FAILED
            )
            code = exc.code if isinstance(exc, TransportError) else "campaign_failed"
            deviation = Deviation(
                1,
                manifest.campaign_id,
                phase.value,
                code,
                str(exc),
                int(self._request_count()),
                len(observations) * 2,
            )
            _atomic_write(deviation_path, json_bytes(deviation.to_json()), overwrite=False)
            raise
        return verification


def request_campaign_cancel(workspace: Path, campaign_id: str) -> Path:
    """Atomically request cooperative cancellation without deleting retained state."""
    if _IDENTIFIER.fullmatch(campaign_id) is None:
        raise OperatorInputError("campaign_id is invalid")
    path = workspace / f"{campaign_id}.cancel"
    _atomic_write(path, b"cancel-requested\n", overwrite=False)
    return path


def retain_preflight_result(workspace: Path, result: PreflightResult) -> Path:
    """Atomically retain one non-overwriting E2/E3 preflight attempt."""
    path = workspace / f"{result.campaign_id}.preflight-attempt-{result.attempt}.json"
    _atomic_write(path, json_bytes(result.to_json()), overwrite=False)
    return path


def load_campaign_checkpoint(workspace: Path, campaign_id: str) -> dict[str, Any]:
    """Load one retained campaign checkpoint."""
    if _IDENTIFIER.fullmatch(campaign_id) is None:
        raise OperatorInputError("campaign_id is invalid")
    return _read_object(workspace / f"{campaign_id}.checkpoint.json", "campaign checkpoint")


def input_inventory_digest(path: Path) -> str:
    """Return the SHA-256 digest of exact private-input inventory bytes."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise OperatorInputError(f"cannot read input inventory: {exc}") from exc


def _read_json_lines(path: Path, contract: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        values = [json.loads(line) for line in lines if line.strip()]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError(f"cannot read {contract}: {exc}") from exc
    if any(not isinstance(value, dict) for value in values):
        raise OperatorInputError(f"{contract} records must be JSON objects")
    return cast(list[dict[str, Any]], values)


def _campaign_memory(value: object) -> CampaignMemory:
    if not isinstance(value, dict) or set(value) != {"memory_id", "content"}:
        raise OperatorInputError("campaign memory has an invalid field set")
    memory_id = value["memory_id"]
    content = value["content"]
    if not isinstance(memory_id, str) or not isinstance(content, str):
        raise OperatorInputError("campaign memory fields must be strings")
    return CampaignMemory(memory_id, content)


def load_campaign_worlds(path: Path) -> tuple[CampaignWorld, ...]:
    """Load the target-visible world pack without evaluator oracles."""
    worlds: list[CampaignWorld] = []
    required = {
        "schema_version",
        "world_id",
        "source_memories",
        "benign_pool",
        "targeted_pool",
        "target_query",
        "non_target_query",
    }
    for value in _read_json_lines(path, "campaign worlds"):
        _exact(value, required, "campaign world")
        if value["schema_version"] != 1:
            raise OperatorInputError("campaign world schema_version must be 1")
        arrays: dict[str, tuple[CampaignMemory, ...]] = {}
        for name in ("source_memories", "benign_pool", "targeted_pool"):
            raw = value[name]
            if not isinstance(raw, list):
                raise OperatorInputError(f"campaign world {name} must be an array")
            arrays[name] = tuple(_campaign_memory(item) for item in raw)
        world_id = value["world_id"]
        target_query = value["target_query"]
        non_target_query = value["non_target_query"]
        if not all(isinstance(item, str) for item in (world_id, target_query, non_target_query)):
            raise OperatorInputError("campaign world identity and queries must be strings")
        worlds.append(
            CampaignWorld(
                world_id=cast(str, world_id),
                source_memories=arrays["source_memories"],
                benign_pool=arrays["benign_pool"],
                targeted_pool=arrays["targeted_pool"],
                target_query=cast(str, target_query),
                non_target_query=cast(str, non_target_query),
            )
        )
    if len({world.world_id for world in worlds}) != len(worlds):
        raise OperatorInputError("campaign world IDs must be unique")
    return tuple(worlds)


def load_evaluator_oracles(path: Path) -> tuple[EvaluatorOracle, ...]:
    """Load evaluator-only oracles separately from target-visible inputs."""
    oracles: list[EvaluatorOracle] = []
    required = {"schema_version", "world_id", "target_memory_id", "non_target_memory_id"}
    for value in _read_json_lines(path, "evaluator oracles"):
        _exact(value, required, "evaluator oracle")
        if value["schema_version"] != 1:
            raise OperatorInputError("evaluator oracle schema_version must be 1")
        raw_fields = (
            value["world_id"],
            value["target_memory_id"],
            value["non_target_memory_id"],
        )
        if any(not isinstance(item, str) or not item for item in raw_fields):
            raise OperatorInputError("evaluator oracle fields must be nonempty strings")
        world_id, target_memory_id, non_target_memory_id = cast(tuple[str, str, str], raw_fields)
        oracles.append(EvaluatorOracle(world_id, target_memory_id, non_target_memory_id))
    if len({oracle.world_id for oracle in oracles}) != len(oracles):
        raise OperatorInputError("evaluator oracle world IDs must be unique")
    return tuple(oracles)


def load_campaign_contracts(
    target_path: Path, campaign_path: Path, approval_path: Path | None
) -> tuple[ExternalTargetManifest, CampaignManifest, CampaignApproval | None]:
    """Load the three independently bound operator contracts."""
    target = load_external_target_manifest(target_path)
    campaign = load_campaign_manifest(campaign_path)
    approval = None if approval_path is None else load_campaign_approval(approval_path)
    return target, campaign, approval
