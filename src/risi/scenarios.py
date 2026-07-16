"""Strict loading for synthetic, executable RISI reference scenarios."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from risi.canonical import JsonObject, JsonValue, canonical_sha256, freeze_json_object
from risi.evaluator import DecisionOracle, EvaluatorState, MemoryOracle
from risi.models import MemoryRecord, MemoryState
from risi.operator.models import OperatorInputError


@dataclass(frozen=True, slots=True)
class ReferenceRunProtocol:
    """Describe the target-visible deterministic DEP-01 decision protocol.

    Attributes:
        principal_id: Principal issuing the retrieval.
        tenant_id: Tenant authorization boundary.
        query: Synthetic retrieval query.
        top_k: Maximum retrieval results.
        approval_count_fact: World-state fact containing the current approval count.
        minimum_approvals: Target-visible policy threshold.
        required_memory_id: Policy memory needed by the decision provider.
        action_if_below: Proposed action when approvals are below the threshold.
        action_if_met: Proposed action when the threshold is met.
    """

    principal_id: str
    tenant_id: str
    query: str
    top_k: int
    approval_count_fact: str
    minimum_approvals: int
    required_memory_id: str
    action_if_below: str
    action_if_met: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible protocol representation."""
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "query": self.query,
            "top_k": self.top_k,
            "approval_count_fact": self.approval_count_fact,
            "minimum_approvals": self.minimum_approvals,
            "required_memory_id": self.required_memory_id,
            "action_if_below": self.action_if_below,
            "action_if_met": self.action_if_met,
        }


@dataclass(frozen=True, slots=True)
class CrafReferenceProtocol:
    """Describe the target-visible truthful interaction used in WP2B.

    Attributes:
        principal_id: Authorized principal issuing the interaction retrieval.
        tenant_id: Tenant authorization boundary for the interaction.
        query: Truthful synthetic query that retrieves the designated trigger memory.
        top_k: Maximum interaction retrieval results.
        interaction_count: Exact bounded number of interactions.
        trigger_memory_id: Truthful close distractor that activates adaptive state.
    """

    principal_id: str
    tenant_id: str
    query: str
    top_k: int
    interaction_count: int
    trigger_memory_id: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible interaction protocol."""
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "query": self.query,
            "top_k": self.top_k,
            "interaction_count": self.interaction_count,
            "trigger_memory_id": self.trigger_memory_id,
        }


@dataclass(frozen=True, slots=True)
class SyntheticScenario:
    """Contain separated target-visible and evaluator-only scenario state.

    Attributes:
        schema_version: Scenario contract version.
        scenario_id: Stable scenario identifier.
        logical_time: Initial deterministic time.
        facts: Target-visible immutable world facts.
        memories: Target-visible memory records.
        evaluator: Evaluator-only truth and decision oracles.
        protocol: Target-visible reference-run protocol.
        craf_reference: Optional target-visible controlled CRAF interaction protocol.
        seeds: Allowed deterministic seeds.
    """

    schema_version: int
    scenario_id: str
    logical_time: int
    facts: JsonObject
    memories: tuple[MemoryRecord, ...]
    evaluator: EvaluatorState
    protocol: ReferenceRunProtocol
    craf_reference: CrafReferenceProtocol | None
    seeds: tuple[int, ...]

    def __post_init__(self) -> None:
        """Detach the target-visible world facts."""
        object.__setattr__(self, "facts", freeze_json_object(self.facts))
        object.__setattr__(self, "memories", tuple(self.memories))
        object.__setattr__(self, "seeds", tuple(self.seeds))

    def target_view(self) -> dict[str, JsonValue]:
        """Return only state that may be exposed to the target implementation."""
        target: dict[str, JsonValue] = {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "logical_time": self.logical_time,
            "facts": self.facts,
            "initial_memories": [memory.to_json() for memory in self.memories],
            "reference_run": self.protocol.to_json(),
            "seeds": list(self.seeds),
        }
        if self.craf_reference is not None:
            target["craf_reference"] = self.craf_reference.to_json()
        return target

    def evaluator_view(self) -> dict[str, JsonValue]:
        """Return evaluator-only material for evidence capture."""
        return {
            "episode_id": self.evaluator.episode_id,
            "world_state_hash": self.evaluator.world_state_hash,
            "memory_oracles": [
                {
                    "memory_id": oracle.memory_id,
                    "oracle_truth": oracle.oracle_truth,
                    "oracle_criticality": oracle.oracle_criticality,
                    "valid_from": oracle.valid_from,
                    "valid_until": oracle.valid_until,
                    "applicability": oracle.applicability,
                }
                for oracle in self.evaluator.memory_oracles
            ],
            "decision_oracle": {
                "oracle_id": self.evaluator.decision_oracle.oracle_id,
                "episode_id": self.evaluator.decision_oracle.episode_id,
                "safe_actions": list(self.evaluator.decision_oracle.safe_actions),
            },
        }


def _require_object(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OperatorInputError(f"{field_name} must be an object")
    return cast(dict[str, Any], value)


def _require_array(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise OperatorInputError(f"{field_name} must be an array")
    return cast(list[Any], value)


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperatorInputError(f"{field_name} must be a nonempty string")
    return value


def _require_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperatorInputError(f"{field_name} must be an integer")
    return cast(int, value)


def _exact_keys(
    value: dict[str, Any],
    required: set[str],
    field_name: str,
    optional: set[str] | None = None,
) -> None:
    allowed = required | (optional or set())
    missing = required - set(value)
    extra = set(value) - allowed
    if missing:
        raise OperatorInputError(f"{field_name} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        extra_fields = ", ".join(sorted(extra))
        raise OperatorInputError(f"{field_name} contains unknown fields: {extra_fields}")


def _parse_memory(value: Any, scenario_id: str) -> MemoryRecord:
    memory = _require_object(value, "initial_memories item")
    required = {
        "memory_id",
        "content",
        "tenant_id",
        "owner_id",
        "source_id",
        "access_policy",
        "logical_created_at",
        "logical_valid_from",
        "logical_valid_until",
        "state",
        "metadata",
    }
    _exact_keys(memory, required, "initial_memories item", {"system_criticality"})
    access_policy = tuple(
        _require_string(item, "access_policy item")
        for item in _require_array(memory["access_policy"], "access_policy")
    )
    valid_until = memory["logical_valid_until"]
    if valid_until is not None:
        valid_until = _require_integer(valid_until, "logical_valid_until")
    system_criticality = memory.get("system_criticality")
    if system_criticality is not None:
        system_criticality = _require_string(system_criticality, "system_criticality")
    try:
        state = MemoryState(_require_string(memory["state"], "state"))
    except ValueError as exc:
        raise OperatorInputError("state is not a recognized memory state") from exc
    return MemoryRecord(
        memory_id=_require_string(memory["memory_id"], "memory_id"),
        scenario_id=scenario_id,
        tenant_id=_require_string(memory["tenant_id"], "tenant_id"),
        owner_id=_require_string(memory["owner_id"], "owner_id"),
        source_id=_require_string(memory["source_id"], "source_id"),
        content=_require_string(memory["content"], "content"),
        access_policy=access_policy,
        logical_created_at=_require_integer(memory["logical_created_at"], "logical_created_at"),
        logical_valid_from=_require_integer(memory["logical_valid_from"], "logical_valid_from"),
        logical_valid_until=valid_until,
        system_criticality=system_criticality,
        state=state,
        metadata=_require_object(memory["metadata"], "metadata"),
    )


def _parse_protocol(value: Any) -> ReferenceRunProtocol:
    protocol = _require_object(value, "reference_run")
    fields = {
        "principal_id",
        "tenant_id",
        "query",
        "top_k",
        "approval_count_fact",
        "minimum_approvals",
        "required_memory_id",
        "action_if_below",
        "action_if_met",
    }
    _exact_keys(protocol, fields, "reference_run")
    parsed = ReferenceRunProtocol(
        principal_id=_require_string(protocol["principal_id"], "principal_id"),
        tenant_id=_require_string(protocol["tenant_id"], "tenant_id"),
        query=_require_string(protocol["query"], "query"),
        top_k=_require_integer(protocol["top_k"], "top_k"),
        approval_count_fact=_require_string(protocol["approval_count_fact"], "approval_count_fact"),
        minimum_approvals=_require_integer(protocol["minimum_approvals"], "minimum_approvals"),
        required_memory_id=_require_string(protocol["required_memory_id"], "required_memory_id"),
        action_if_below=_require_string(protocol["action_if_below"], "action_if_below"),
        action_if_met=_require_string(protocol["action_if_met"], "action_if_met"),
    )
    if parsed.top_k <= 0 or parsed.minimum_approvals <= 0:
        raise OperatorInputError("reference_run numeric limits must be positive")
    return parsed


def _parse_craf_reference(value: Any) -> CrafReferenceProtocol:
    protocol = _require_object(value, "craf_reference")
    fields = {
        "principal_id",
        "tenant_id",
        "query",
        "top_k",
        "interaction_count",
        "trigger_memory_id",
    }
    _exact_keys(protocol, fields, "craf_reference")
    parsed = CrafReferenceProtocol(
        principal_id=_require_string(protocol["principal_id"], "craf_reference.principal_id"),
        tenant_id=_require_string(protocol["tenant_id"], "craf_reference.tenant_id"),
        query=_require_string(protocol["query"], "craf_reference.query"),
        top_k=_require_integer(protocol["top_k"], "craf_reference.top_k"),
        interaction_count=_require_integer(
            protocol["interaction_count"], "craf_reference.interaction_count"
        ),
        trigger_memory_id=_require_string(
            protocol["trigger_memory_id"], "craf_reference.trigger_memory_id"
        ),
    )
    if parsed.top_k <= 0:
        raise OperatorInputError("craf_reference.top_k must be positive")
    if parsed.interaction_count != 1:
        raise OperatorInputError("craf_reference.interaction_count must be exactly 1 in M1")
    return parsed


def _parse_evaluator(
    value: Any,
    episode_id: str,
    memories: tuple[MemoryRecord, ...],
    world_state: dict[str, Any],
) -> EvaluatorState:
    evaluator = _require_object(value, "evaluator_only")
    _exact_keys(
        evaluator,
        {"world_state_hash", "memory_oracles", "decision_oracle"},
        "evaluator_only",
    )
    expected_world_hash = canonical_sha256(world_state)
    supplied_world_hash = _require_string(evaluator["world_state_hash"], "world_state_hash")
    if supplied_world_hash != expected_world_hash:
        raise OperatorInputError("evaluator_only.world_state_hash does not match world_state")
    by_id = {memory.memory_id: memory for memory in memories}
    memory_oracles: list[MemoryOracle] = []
    for item in _require_array(evaluator["memory_oracles"], "memory_oracles"):
        oracle = _require_object(item, "memory_oracle")
        _exact_keys(
            oracle,
            {"memory_id", "oracle_truth", "oracle_criticality", "applicability"},
            "memory_oracle",
        )
        memory_id = _require_string(oracle["memory_id"], "memory_oracle.memory_id")
        if memory_id not in by_id:
            raise OperatorInputError("memory oracle references an unknown memory")
        if not isinstance(oracle["oracle_truth"], bool) or not isinstance(
            oracle["oracle_criticality"], bool
        ):
            raise OperatorInputError("memory oracle truth and criticality must be booleans")
        source = by_id[memory_id]
        memory_oracles.append(
            MemoryOracle(
                memory_id=memory_id,
                oracle_truth=oracle["oracle_truth"],
                oracle_criticality=oracle["oracle_criticality"],
                valid_from=source.logical_valid_from,
                valid_until=source.logical_valid_until,
                applicability=_require_object(oracle["applicability"], "applicability"),
            )
        )
    decision = _require_object(evaluator["decision_oracle"], "decision_oracle")
    _exact_keys(decision, {"oracle_id", "safe_actions"}, "decision_oracle")
    safe_actions = tuple(
        _require_string(item, "safe_actions item")
        for item in _require_array(decision["safe_actions"], "safe_actions")
    )
    return EvaluatorState(
        episode_id=episode_id,
        world_state_hash=supplied_world_hash,
        memory_oracles=tuple(memory_oracles),
        decision_oracle=DecisionOracle(
            oracle_id=_require_string(decision["oracle_id"], "oracle_id"),
            episode_id=episode_id,
            safe_actions=safe_actions,
        ),
    )


def _read_scenario_file(
    path: Path, max_input_bytes: int, expected_sha256: str | None
) -> dict[str, Any]:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise OperatorInputError(f"cannot read scenario: {exc}") from exc
    if len(content) > max_input_bytes:
        raise OperatorInputError("scenario exceeds the approved input_bytes limit")
    if expected_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_sha256:
        raise OperatorInputError("scenario content does not match manifest scenario_sha256")
    try:
        raw = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError(f"cannot read scenario: {exc}") from exc
    return _require_object(raw, "scenario")


def _validate_craf_reference(
    protocol: CrafReferenceProtocol,
    decision_protocol: ReferenceRunProtocol,
    memories: tuple[MemoryRecord, ...],
    evaluator: EvaluatorState,
    logical_time: int,
) -> None:
    trigger = next(
        (memory for memory in memories if memory.memory_id == protocol.trigger_memory_id),
        None,
    )
    if trigger is None:
        raise OperatorInputError("craf_reference trigger_memory_id is unknown")
    if trigger.memory_id == decision_protocol.required_memory_id:
        raise OperatorInputError("craf_reference trigger must differ from the required memory")
    if trigger.tenant_id != protocol.tenant_id:
        raise OperatorInputError("craf_reference trigger belongs to another tenant")
    if protocol.principal_id not in trigger.access_policy:
        raise OperatorInputError("craf_reference principal is not authorized for the trigger")
    currently_available = (
        trigger.state is MemoryState.CURRENT
        and logical_time >= trigger.logical_valid_from
        and (trigger.logical_valid_until is None or logical_time < trigger.logical_valid_until)
    )
    if not currently_available:
        raise OperatorInputError("craf_reference trigger is not currently available")
    trigger_oracle = next(
        (oracle for oracle in evaluator.memory_oracles if oracle.memory_id == trigger.memory_id),
        None,
    )
    if trigger_oracle is None or not trigger_oracle.oracle_truth:
        raise OperatorInputError("craf_reference trigger requires a truthful evaluator oracle")


def load_scenario(
    path: Path,
    *,
    run_id: str,
    seed: int,
    max_input_bytes: int,
    max_memory_records: int,
    expected_sha256: str | None = None,
) -> SyntheticScenario:
    """Load and semantically validate an executable synthetic scenario.

    Args:
        path: Scenario JSON path already contained by the trusted scenario root.
        run_id: Run identifier used to derive the episode identity.
        seed: Requested deterministic seed.
        max_input_bytes: Safety-kernel input-size ceiling.
        max_memory_records: Safety-kernel source-memory ceiling.
        expected_sha256: Optional manifest-bound digest of the exact scenario bytes.

    Returns:
        Structurally separated target and evaluator scenario state.

    Raises:
        OperatorInputError: If parsing or semantic validation fails.
    """
    scenario = _read_scenario_file(path, max_input_bytes, expected_sha256)
    required = {
        "schema_version",
        "scenario_id",
        "domain",
        "phenomenon",
        "world_state",
        "principals",
        "initial_memories",
        "evaluator_only",
        "baseline_history",
        "attacker_model",
        "craf",
        "nuisance_factors",
        "seeds",
        "reference_run",
    }
    _exact_keys(scenario, required, "scenario", {"craf_reference"})
    schema_version = _require_integer(scenario["schema_version"], "schema_version")
    if schema_version != 1:
        raise OperatorInputError("scenario schema_version must be 1")
    scenario_id = _require_string(scenario["scenario_id"], "scenario_id")
    world_state = _require_object(scenario["world_state"], "world_state")
    _exact_keys(world_state, {"logical_time", "facts", "policies"}, "world_state")
    logical_time = _require_integer(world_state["logical_time"], "logical_time")
    facts = _require_object(world_state["facts"], "facts")
    memories = tuple(
        _parse_memory(item, scenario_id)
        for item in _require_array(scenario["initial_memories"], "initial_memories")
    )
    if len(memories) > max_memory_records:
        raise OperatorInputError("scenario exceeds the approved memory_records limit")
    memory_ids = {memory.memory_id for memory in memories}
    if len(memory_ids) != len(memories):
        raise OperatorInputError("initial_memories must contain unique memory IDs")
    seeds = tuple(
        _require_integer(item, "seeds item") for item in _require_array(scenario["seeds"], "seeds")
    )
    if seed not in seeds:
        raise OperatorInputError("manifest seed is not declared by the scenario")
    protocol = _parse_protocol(scenario["reference_run"])
    if protocol.required_memory_id not in memory_ids:
        raise OperatorInputError("reference_run requires an unknown memory")
    if protocol.approval_count_fact not in facts:
        raise OperatorInputError("reference_run requires an unknown world-state fact")
    episode_id = f"{run_id}-episode-0001"
    evaluator = _parse_evaluator(scenario["evaluator_only"], episode_id, memories, world_state)
    craf_reference = (
        None
        if "craf_reference" not in scenario
        else _parse_craf_reference(scenario["craf_reference"])
    )
    if craf_reference is not None:
        _validate_craf_reference(
            craf_reference,
            protocol,
            memories,
            evaluator,
            logical_time,
        )
    return SyntheticScenario(
        schema_version=schema_version,
        scenario_id=scenario_id,
        logical_time=logical_time,
        facts=facts,
        memories=memories,
        evaluator=evaluator,
        protocol=protocol,
        craf_reference=craf_reference,
        seeds=seeds,
    )
