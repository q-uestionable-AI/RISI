"""Versioned machine contracts for operator-controlled RISI runs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, cast

from risi.canonical import JsonObject, JsonValue, canonical_sha256, freeze_json_object

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class OperatorInputError(ValueError):
    """Raised when an operator-supplied machine contract is invalid."""


def _validate_identifier(value: str, field_name: str) -> None:
    if _IDENTIFIER.fullmatch(value) is None:
        raise OperatorInputError(f"{field_name} must be a lowercase registered identifier")


def _validate_scenario_reference(path_value: str, digest: str) -> None:
    path = PurePosixPath(path_value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise OperatorInputError("scenario_path must remain beneath the scenario root")
    if "\\" in path_value:
        raise OperatorInputError("scenario_path must use POSIX separators")
    if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise OperatorInputError("scenario_sha256 must be a lowercase SHA-256 digest")


class Capability(StrEnum):
    """Closed capability vocabulary understood by the safety kernel."""

    SCENARIO_READ = "scenario.read"
    ARTIFACT_WRITE = "artifact.write"
    REFERENCE_EXECUTE = "reference.execute"
    EVIDENCE_VERIFY = "evidence.verify"
    TARGET_CONNECT = "target.connect"
    # This is a capability identifier, not credential material.
    SECRET_READ = "secret.read"  # noqa: S105  # nosec B105
    KNOWLEDGE_BASE_CREATE = "knowledge-base.create"
    KNOWLEDGE_BASE_INSPECT = "knowledge-base.inspect"
    KNOWLEDGE_BASE_DELETE = "knowledge-base.delete"
    DOCUMENT_CREATE = "document.create"
    DOCUMENT_INSPECT = "document.inspect"
    DOCUMENT_DELETE = "document.delete"
    RETRIEVAL_EXECUTE = "retrieval.execute"
    HEALTH_READ = "health.read"


class ExecutionProfile(StrEnum):
    """Implemented execution profiles."""

    LOCAL_REFERENCE = "local-reference"
    ISOLATED_DIFY_KNOWLEDGE = "isolated-dify-knowledge"


class ResultStatus(StrEnum):
    """Stable command-result status vocabulary."""

    OK = "ok"
    ERROR = "error"
    BLOCKED = "blocked"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    """Bound resource use requested by a run manifest.

    Attributes:
        episodes: Maximum episodes in the run.
        retrieval_calls: Maximum retrieval operations.
        logical_steps: Maximum deterministic episode-start, retrieval, and decision operations.
        input_bytes: Maximum scenario input size.
        memory_records: Maximum source memory records.
        artifact_bytes: Maximum evidence-bundle size.
    """

    episodes: int
    retrieval_calls: int
    logical_steps: int
    input_bytes: int
    memory_records: int
    artifact_bytes: int

    def __post_init__(self) -> None:
        """Validate that every resource ceiling is positive."""
        for name in (
            "episodes",
            "retrieval_calls",
            "logical_steps",
            "input_bytes",
            "memory_records",
            "artifact_bytes",
        ):
            if getattr(self, name) <= 0:
                raise OperatorInputError(f"limits.{name} must be positive")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible limits representation."""
        return {
            "episodes": self.episodes,
            "retrieval_calls": self.retrieval_calls,
            "logical_steps": self.logical_steps,
            "input_bytes": self.input_bytes,
            "memory_records": self.memory_records,
            "artifact_bytes": self.artifact_bytes,
        }


@dataclass(frozen=True, slots=True)
class RunManifest:
    """Describe one bounded, reproducible harness run.

    Attributes:
        schema_version: Operator-contract version.
        run_id: Filesystem-safe run identifier.
        profile: Execution profile requested by the operator.
        scenario_path: POSIX-style path relative to the scenario root.
        scenario_sha256: Digest of the exact approved scenario file bytes.
        seed: Deterministic scenario seed.
        adapter: Registered memory adapter name.
        decision_provider: Registered decision-provider name.
        policy: Registered memory policy name.
        capabilities: Capabilities requested from the safety kernel.
        limits: Requested resource ceilings.
    """

    schema_version: int
    run_id: str
    profile: ExecutionProfile
    scenario_path: str
    scenario_sha256: str
    seed: int
    adapter: str
    decision_provider: str
    policy: str
    capabilities: tuple[Capability, ...]
    limits: ExecutionLimits

    def __post_init__(self) -> None:
        """Validate identifiers, relative paths, seed, and capabilities."""
        if self.schema_version != 1:
            raise OperatorInputError("manifest schema_version must be 1")
        _validate_identifier(self.run_id, "run_id")
        _validate_scenario_reference(self.scenario_path, self.scenario_sha256)
        if self.seed < 0:
            raise OperatorInputError("seed must be nonnegative")
        for name in ("adapter", "decision_provider", "policy"):
            _validate_identifier(getattr(self, name), name)
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        if not self.capabilities:
            raise OperatorInputError("capabilities must not be empty")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise OperatorInputError("capabilities must contain unique values")

    @property
    def digest(self) -> str:
        """Return the canonical manifest digest."""
        return canonical_sha256(self.to_json())

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible manifest representation."""
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "profile": self.profile.value,
            "scenario_path": self.scenario_path,
            "scenario_sha256": self.scenario_sha256,
            "seed": self.seed,
            "adapter": self.adapter,
            "decision_provider": self.decision_provider,
            "policy": self.policy,
            "capabilities": [capability.value for capability in self.capabilities],
            "limits": self.limits.to_json(),
        }


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """Bind human approval evidence to exact manifest material.

    This record provides provenance and change detection. It is not authentication; deployments
    needing a stronger boundary must protect or sign it outside the agent's execution context.

    Attributes:
        schema_version: Approval-contract version.
        manifest_sha256: Digest of the approved run manifest.
        approved_by: Operator-supplied reviewer identity.
        capabilities: Exact approved capability scope.
        note: Optional human context.
    """

    schema_version: int
    manifest_sha256: str
    approved_by: str
    capabilities: tuple[Capability, ...]
    note: str = ""

    def __post_init__(self) -> None:
        """Validate the approval version, digest, identity, and scope."""
        if self.schema_version != 1:
            raise OperatorInputError("approval schema_version must be 1")
        if not re.fullmatch(r"[a-f0-9]{64}", self.manifest_sha256):
            raise OperatorInputError("manifest_sha256 must be a lowercase SHA-256 digest")
        if not self.approved_by.strip():
            raise OperatorInputError("approved_by must not be empty")
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        if len(self.capabilities) != len(set(self.capabilities)):
            raise OperatorInputError("approval capabilities must contain unique values")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible approval representation."""
        return {
            "schema_version": self.schema_version,
            "manifest_sha256": self.manifest_sha256,
            "approved_by": self.approved_by,
            "capabilities": [capability.value for capability in self.capabilities],
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class ResultError:
    """Describe one stable machine-readable command failure.

    Attributes:
        code: Stable error code.
        message: Human-readable explanation.
        field: Optional contract field associated with the error.
    """

    code: str
    message: str
    field: str | None = None

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible error representation."""
        return {"code": self.code, "message": self.message, "field": self.field}


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Provide a stable result envelope for human and autonomous operators.

    Attributes:
        command: CLI or application-service operation.
        status: Stable outcome status.
        run_id: Associated run identifier, when known.
        data: Structured successful or diagnostic result data.
        errors: Structured failures or policy denials.
    """

    command: str
    status: ResultStatus
    run_id: str | None = None
    data: JsonObject = field(default_factory=dict)
    errors: tuple[ResultError, ...] = ()
    schema_version: int = 1

    def __post_init__(self) -> None:
        """Validate and detach result-envelope fields."""
        if self.schema_version != 1:
            raise ValueError("result schema_version must be 1")
        if not self.command.strip():
            raise ValueError("command must not be empty")
        object.__setattr__(self, "data", freeze_json_object(self.data))
        object.__setattr__(self, "errors", tuple(self.errors))
        if self.status is ResultStatus.OK and self.errors:
            raise ValueError("successful results must not contain errors")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible result envelope."""
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "status": self.status.value,
            "run_id": self.run_id,
            "data": self.data,
            "errors": [error.to_json() for error in self.errors],
        }


def _load_object(path: Path, contract: str) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError(f"cannot read {contract}: {exc}") from exc
    if not isinstance(value, dict):
        raise OperatorInputError(f"{contract} must be a JSON object")
    return cast(dict[str, Any], value)


def _require_exact_keys(
    value: dict[str, Any], required: set[str], contract: str, optional: set[str] | None = None
) -> None:
    allowed = required | (optional or set())
    missing = required - set(value)
    extra = set(value) - allowed
    if missing:
        raise OperatorInputError(f"{contract} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise OperatorInputError(f"{contract} contains unknown fields: {', '.join(sorted(extra))}")


def _require_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperatorInputError(f"{field_name} must be an integer")
    return cast(int, value)


def _require_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise OperatorInputError(f"{field_name} must be a string")
    return value


def _parse_capabilities(value: Any, field_name: str) -> tuple[Capability, ...]:
    if not isinstance(value, list):
        raise OperatorInputError(f"{field_name} must be an array")
    try:
        return tuple(Capability(_require_str(item, field_name)) for item in value)
    except ValueError as exc:
        raise OperatorInputError(f"{field_name} contains an unknown capability") from exc


def load_run_manifest(path: Path) -> RunManifest:
    """Load and strictly parse a run manifest.

    Args:
        path: JSON manifest path.

    Returns:
        Validated immutable run manifest.

    Raises:
        OperatorInputError: If the file or contract is invalid.
    """
    value = _load_object(path, "run manifest")
    required = {
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
    _require_exact_keys(value, required, "run manifest")
    limits_value = value["limits"]
    if not isinstance(limits_value, dict):
        raise OperatorInputError("limits must be an object")
    limit_fields = {
        "episodes",
        "retrieval_calls",
        "logical_steps",
        "input_bytes",
        "memory_records",
        "artifact_bytes",
    }
    _require_exact_keys(limits_value, limit_fields, "limits")
    try:
        profile = ExecutionProfile(_require_str(value["profile"], "profile"))
    except ValueError as exc:
        raise OperatorInputError("profile is not implemented") from exc
    return RunManifest(
        schema_version=_require_int(value["schema_version"], "schema_version"),
        run_id=_require_str(value["run_id"], "run_id"),
        profile=profile,
        scenario_path=_require_str(value["scenario_path"], "scenario_path"),
        scenario_sha256=_require_str(value["scenario_sha256"], "scenario_sha256"),
        seed=_require_int(value["seed"], "seed"),
        adapter=_require_str(value["adapter"], "adapter"),
        decision_provider=_require_str(value["decision_provider"], "decision_provider"),
        policy=_require_str(value["policy"], "policy"),
        capabilities=_parse_capabilities(value["capabilities"], "capabilities"),
        limits=ExecutionLimits(
            **{name: _require_int(limits_value[name], f"limits.{name}") for name in limit_fields}
        ),
    )


def load_approval_record(path: Path) -> ApprovalRecord:
    """Load and strictly parse approval evidence.

    Args:
        path: JSON approval-record path.

    Returns:
        Validated immutable approval record.

    Raises:
        OperatorInputError: If the file or contract is invalid.
    """
    value = _load_object(path, "approval record")
    required = {
        "schema_version",
        "manifest_sha256",
        "approved_by",
        "capabilities",
        "note",
    }
    _require_exact_keys(value, required, "approval record")
    return ApprovalRecord(
        schema_version=_require_int(value["schema_version"], "schema_version"),
        manifest_sha256=_require_str(value["manifest_sha256"], "manifest_sha256"),
        approved_by=_require_str(value["approved_by"], "approved_by"),
        capabilities=_parse_capabilities(value["capabilities"], "capabilities"),
        note=_require_str(value["note"], "note"),
    )
