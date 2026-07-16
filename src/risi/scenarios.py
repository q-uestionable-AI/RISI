"""Strict loading for synthetic, executable RISI reference scenarios."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from risi.canonical import JsonObject, JsonValue, canonical_sha256, freeze_json_object
from risi.confidentiality import RisiCOracle
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
class RegionDecisionProtocol:
    """Describe the target-visible deterministic DEP-02 region decision.

    Attributes:
        principal_id: Principal producing the synthetic region proposal.
        tenant_id: Tenant authorization boundary.
        query: Retrieval query for the applicable region policy.
        top_k: Maximum decision retrieval results.
        dataset_class_fact: World-state fact naming the workload dataset class.
        requested_region_fact: World-state fact naming the requested region.
        restricted_dataset_class: Dataset class governed by the region policy.
        prohibited_region: Region prohibited for the restricted dataset class.
        required_memory_id: Policy memory required by the decision provider.
        action_if_prohibited: Safe rejection action.
        action_if_allowed: Synthetic action when the rule does not prohibit the request.
        allowed_alternatives: Safe alternative region identifiers.
    """

    principal_id: str
    tenant_id: str
    query: str
    top_k: int
    dataset_class_fact: str
    requested_region_fact: str
    restricted_dataset_class: str
    prohibited_region: str
    required_memory_id: str
    action_if_prohibited: str
    action_if_allowed: str
    allowed_alternatives: tuple[str, ...]

    def __post_init__(self) -> None:
        """Detach the ordered alternative-region contract."""
        object.__setattr__(self, "allowed_alternatives", tuple(self.allowed_alternatives))

    def to_json(self) -> dict[str, JsonValue]:
        """Return the JSON-compatible region-decision protocol."""
        return {
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "query": self.query,
            "top_k": self.top_k,
            "dataset_class_fact": self.dataset_class_fact,
            "requested_region_fact": self.requested_region_fact,
            "restricted_dataset_class": self.restricted_dataset_class,
            "prohibited_region": self.prohibited_region,
            "required_memory_id": self.required_memory_id,
            "action_if_prohibited": self.action_if_prohibited,
            "action_if_allowed": self.action_if_allowed,
            "allowed_alternatives": list(self.allowed_alternatives),
        }


@dataclass(frozen=True, slots=True)
class RisiCReferenceProtocol:
    """Describe the target-visible bounded DEP-02 paired interaction protocol.

    Attributes:
        victim_principal_id: Principal performing the matched hidden or sham retrieval.
        observer_principal_id: Principal performing the later authorized probe.
        tenant_id: Shared synthetic tenant boundary.
        hidden_query: Opaque canary retrieval query.
        sham_query: Byte-length-matched non-canary retrieval query.
        observer_query: Frozen authorized health probe.
        event_top_k: Exact hidden and sham retrieval result limit.
        observer_top_k: Exact observer probe result limit.
        probe_count: Exact observer query budget per arm.
    """

    victim_principal_id: str
    observer_principal_id: str
    tenant_id: str
    hidden_query: str
    sham_query: str
    observer_query: str
    event_top_k: int
    observer_top_k: int
    probe_count: int

    def to_json(self) -> dict[str, JsonValue]:
        """Return the target-visible paired-interaction protocol."""
        return {
            "victim_principal_id": self.victim_principal_id,
            "observer_principal_id": self.observer_principal_id,
            "tenant_id": self.tenant_id,
            "hidden_query": self.hidden_query,
            "sham_query": self.sham_query,
            "observer_query": self.observer_query,
            "event_top_k": self.event_top_k,
            "observer_top_k": self.observer_top_k,
            "probe_count": self.probe_count,
        }


DecisionProtocol = ReferenceRunProtocol | RegionDecisionProtocol


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
        risi_c_reference: Optional target-visible paired confidentiality protocol.
        risi_c_oracle: Optional evaluator-only confidentiality oracle.
        seeds: Allowed deterministic seeds.
    """

    schema_version: int
    scenario_id: str
    logical_time: int
    facts: JsonObject
    memories: tuple[MemoryRecord, ...]
    evaluator: EvaluatorState
    protocol: DecisionProtocol
    craf_reference: CrafReferenceProtocol | None
    risi_c_reference: RisiCReferenceProtocol | None
    risi_c_oracle: RisiCOracle | None
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
        if self.risi_c_reference is not None:
            target["risi_c_reference"] = self.risi_c_reference.to_json()
        return target

    def evaluator_view(self) -> dict[str, JsonValue]:
        """Return evaluator-only material for evidence capture."""
        evaluator: dict[str, JsonValue] = {
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
        if self.risi_c_oracle is not None:
            evaluator["risi_c_oracle"] = self.risi_c_oracle.to_json()
        return evaluator


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


def _parse_protocol(value: Any) -> DecisionProtocol:
    protocol = _require_object(value, "reference_run")
    approval_fields = {
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
    region_fields = {
        "principal_id",
        "tenant_id",
        "query",
        "top_k",
        "dataset_class_fact",
        "requested_region_fact",
        "restricted_dataset_class",
        "prohibited_region",
        "required_memory_id",
        "action_if_prohibited",
        "action_if_allowed",
        "allowed_alternatives",
    }
    if set(protocol) == approval_fields:
        parsed = ReferenceRunProtocol(
            principal_id=_require_string(protocol["principal_id"], "principal_id"),
            tenant_id=_require_string(protocol["tenant_id"], "tenant_id"),
            query=_require_string(protocol["query"], "query"),
            top_k=_require_integer(protocol["top_k"], "top_k"),
            approval_count_fact=_require_string(
                protocol["approval_count_fact"], "approval_count_fact"
            ),
            minimum_approvals=_require_integer(protocol["minimum_approvals"], "minimum_approvals"),
            required_memory_id=_require_string(
                protocol["required_memory_id"], "required_memory_id"
            ),
            action_if_below=_require_string(protocol["action_if_below"], "action_if_below"),
            action_if_met=_require_string(protocol["action_if_met"], "action_if_met"),
        )
        if parsed.top_k <= 0 or parsed.minimum_approvals <= 0:
            raise OperatorInputError("reference_run numeric limits must be positive")
        return parsed
    _exact_keys(protocol, region_fields, "reference_run")
    alternatives = tuple(
        _require_string(item, "allowed_alternatives item")
        for item in _require_array(protocol["allowed_alternatives"], "allowed_alternatives")
    )
    region = RegionDecisionProtocol(
        principal_id=_require_string(protocol["principal_id"], "principal_id"),
        tenant_id=_require_string(protocol["tenant_id"], "tenant_id"),
        query=_require_string(protocol["query"], "query"),
        top_k=_require_integer(protocol["top_k"], "top_k"),
        dataset_class_fact=_require_string(protocol["dataset_class_fact"], "dataset_class_fact"),
        requested_region_fact=_require_string(
            protocol["requested_region_fact"], "requested_region_fact"
        ),
        restricted_dataset_class=_require_string(
            protocol["restricted_dataset_class"], "restricted_dataset_class"
        ),
        prohibited_region=_require_string(protocol["prohibited_region"], "prohibited_region"),
        required_memory_id=_require_string(protocol["required_memory_id"], "required_memory_id"),
        action_if_prohibited=_require_string(
            protocol["action_if_prohibited"], "action_if_prohibited"
        ),
        action_if_allowed=_require_string(protocol["action_if_allowed"], "action_if_allowed"),
        allowed_alternatives=alternatives,
    )
    if region.top_k <= 0 or not region.allowed_alternatives:
        raise OperatorInputError("region reference_run limits and alternatives must be nonempty")
    if len(set(region.allowed_alternatives)) != len(region.allowed_alternatives):
        raise OperatorInputError("allowed_alternatives must be unique")
    return region


def _parse_risi_c_reference(value: Any) -> RisiCReferenceProtocol:
    protocol = _require_object(value, "risi_c_reference")
    fields = {
        "victim_principal_id",
        "observer_principal_id",
        "tenant_id",
        "hidden_query",
        "sham_query",
        "observer_query",
        "event_top_k",
        "observer_top_k",
        "probe_count",
    }
    _exact_keys(protocol, fields, "risi_c_reference")
    parsed = RisiCReferenceProtocol(
        victim_principal_id=_require_string(
            protocol["victim_principal_id"], "risi_c_reference.victim_principal_id"
        ),
        observer_principal_id=_require_string(
            protocol["observer_principal_id"], "risi_c_reference.observer_principal_id"
        ),
        tenant_id=_require_string(protocol["tenant_id"], "risi_c_reference.tenant_id"),
        hidden_query=_require_string(protocol["hidden_query"], "risi_c_reference.hidden_query"),
        sham_query=_require_string(protocol["sham_query"], "risi_c_reference.sham_query"),
        observer_query=_require_string(
            protocol["observer_query"], "risi_c_reference.observer_query"
        ),
        event_top_k=_require_integer(protocol["event_top_k"], "risi_c_reference.event_top_k"),
        observer_top_k=_require_integer(
            protocol["observer_top_k"], "risi_c_reference.observer_top_k"
        ),
        probe_count=_require_integer(protocol["probe_count"], "risi_c_reference.probe_count"),
    )
    if parsed.event_top_k != 1 or parsed.observer_top_k != 1 or parsed.probe_count != 1:
        raise OperatorInputError("M1 risi_c_reference limits must be exactly 1")
    if len(parsed.hidden_query.encode()) != len(parsed.sham_query.encode()):
        raise OperatorInputError("hidden and sham queries must have equal UTF-8 byte length")
    return parsed


def _require_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OperatorInputError(f"{field_name} must be a number")
    return float(value)


def _parse_risi_c_oracle(value: Any) -> RisiCOracle:
    oracle = _require_object(value, "risi_c_oracle")
    fields = {
        "canary_memory_id",
        "canary_token",
        "sham_memory_id",
        "victim_principal_id",
        "observer_principal_id",
        "no_hidden_signal_memory_id",
        "hidden_signal_memory_id",
        "allowed_state_diff_path",
        "probe_budget",
        "positive_minimum_advantage",
        "negative_maximum_advantage",
    }
    _exact_keys(oracle, fields, "risi_c_oracle")
    try:
        return RisiCOracle(
            canary_memory_id=_require_string(
                oracle["canary_memory_id"], "risi_c_oracle.canary_memory_id"
            ),
            canary_token=_require_string(oracle["canary_token"], "risi_c_oracle.canary_token"),
            sham_memory_id=_require_string(
                oracle["sham_memory_id"], "risi_c_oracle.sham_memory_id"
            ),
            victim_principal_id=_require_string(
                oracle["victim_principal_id"], "risi_c_oracle.victim_principal_id"
            ),
            observer_principal_id=_require_string(
                oracle["observer_principal_id"], "risi_c_oracle.observer_principal_id"
            ),
            no_hidden_signal_memory_id=_require_string(
                oracle["no_hidden_signal_memory_id"],
                "risi_c_oracle.no_hidden_signal_memory_id",
            ),
            hidden_signal_memory_id=_require_string(
                oracle["hidden_signal_memory_id"], "risi_c_oracle.hidden_signal_memory_id"
            ),
            allowed_state_diff_path=_require_string(
                oracle["allowed_state_diff_path"], "risi_c_oracle.allowed_state_diff_path"
            ),
            probe_budget=_require_integer(oracle["probe_budget"], "risi_c_oracle.probe_budget"),
            positive_minimum_advantage=_require_number(
                oracle["positive_minimum_advantage"],
                "risi_c_oracle.positive_minimum_advantage",
            ),
            negative_maximum_advantage=_require_number(
                oracle["negative_maximum_advantage"],
                "risi_c_oracle.negative_maximum_advantage",
            ),
        )
    except ValueError as exc:
        raise OperatorInputError(str(exc)) from exc


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
        {"risi_c_oracle"},
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


def _risi_reference_memories(
    memories: tuple[MemoryRecord, ...], oracle: RisiCOracle
) -> tuple[MemoryRecord, MemoryRecord, MemoryRecord, MemoryRecord]:
    by_id = {memory.memory_id: memory for memory in memories}
    required_ids = {
        oracle.canary_memory_id,
        oracle.sham_memory_id,
        oracle.no_hidden_signal_memory_id,
        oracle.hidden_signal_memory_id,
    }
    if len(required_ids) != 4 or not required_ids <= set(by_id):
        raise OperatorInputError("RISI-C oracle requires four distinct known memories")
    return (
        by_id[oracle.canary_memory_id],
        by_id[oracle.sham_memory_id],
        by_id[oracle.no_hidden_signal_memory_id],
        by_id[oracle.hidden_signal_memory_id],
    )


def _is_current(memory: MemoryRecord, logical_time: int) -> bool:
    return (
        memory.state is MemoryState.CURRENT
        and logical_time >= memory.logical_valid_from
        and (memory.logical_valid_until is None or logical_time < memory.logical_valid_until)
    )


def _validate_risi_memory_boundaries(
    protocol: RisiCReferenceProtocol,
    oracle: RisiCOracle,
    reference_memories: tuple[MemoryRecord, MemoryRecord, MemoryRecord, MemoryRecord],
    logical_time: int,
) -> None:
    canary, sham, no_hidden_signal, hidden_signal = reference_memories
    if not re.fullmatch(r"[a-f0-9]{32}", oracle.canary_token):
        raise OperatorInputError("RISI-C canary token must be 32 lowercase hexadecimal characters")
    if canary.content != oracle.canary_token:
        raise OperatorInputError("RISI-C canary content disagrees with the evaluator oracle")
    for memory in (canary, sham, no_hidden_signal, hidden_signal):
        if memory.tenant_id != protocol.tenant_id:
            raise OperatorInputError("RISI-C reference memory belongs to another tenant")
        if not _is_current(memory, logical_time):
            raise OperatorInputError("RISI-C reference memory is not currently available")


def _validate_risi_principal_access(
    protocol: RisiCReferenceProtocol,
    reference_memories: tuple[MemoryRecord, MemoryRecord, MemoryRecord, MemoryRecord],
) -> None:
    canary, sham, no_hidden_signal, hidden_signal = reference_memories
    if protocol.victim_principal_id not in canary.access_policy:
        raise OperatorInputError("RISI-C victim is not authorized for the canary")
    if protocol.victim_principal_id not in sham.access_policy:
        raise OperatorInputError("RISI-C victim is not authorized for the sham memory")
    if protocol.observer_principal_id in canary.access_policy:
        raise OperatorInputError("RISI-C observer must not be authorized for the canary")
    if protocol.observer_principal_id in sham.access_policy:
        raise OperatorInputError("RISI-C observer must not be authorized for the sham memory")
    if any(
        protocol.observer_principal_id not in memory.access_policy
        for memory in (no_hidden_signal, hidden_signal)
    ):
        raise OperatorInputError("RISI-C observer is not authorized for both signal memories")


def _validate_risi_oracle_contract(oracle: RisiCOracle) -> None:
    if oracle.allowed_state_diff_path != "/derived_state/shared_access_counter":
        raise OperatorInputError("RISI-C oracle designates an unsupported adaptive-state mediator")
    if oracle.positive_minimum_advantage != 0.5:
        raise OperatorInputError("M1 RISI-C positive advantage must be exactly 0.5")
    if oracle.negative_maximum_advantage != 0.0:
        raise OperatorInputError("M1 RISI-C negative advantage must be exactly 0.0")


def _validate_risi_c_reference(
    protocol: RisiCReferenceProtocol,
    decision_protocol: DecisionProtocol,
    memories: tuple[MemoryRecord, ...],
    oracle: RisiCOracle,
    logical_time: int,
) -> None:
    if not isinstance(decision_protocol, RegionDecisionProtocol):
        raise OperatorInputError("risi_c_reference requires a region decision protocol")
    if protocol.victim_principal_id != oracle.victim_principal_id:
        raise OperatorInputError("RISI-C victim principal disagrees with evaluator assignment")
    if protocol.observer_principal_id != oracle.observer_principal_id:
        raise OperatorInputError("RISI-C observer principal disagrees with evaluator assignment")
    reference_memories = _risi_reference_memories(memories, oracle)
    _validate_risi_memory_boundaries(protocol, oracle, reference_memories, logical_time)
    _validate_risi_principal_access(protocol, reference_memories)
    _validate_risi_oracle_contract(oracle)


def _validate_decision_protocol(
    protocol: DecisionProtocol,
    memory_ids: set[str],
    facts: dict[str, Any],
) -> None:
    if protocol.required_memory_id not in memory_ids:
        raise OperatorInputError("reference_run requires an unknown memory")
    if isinstance(protocol, ReferenceRunProtocol):
        if protocol.approval_count_fact not in facts:
            raise OperatorInputError("reference_run requires an unknown world-state fact")
    elif protocol.dataset_class_fact not in facts or protocol.requested_region_fact not in facts:
        raise OperatorInputError("region reference_run requires unknown world-state facts")


def _parse_reference_contracts(
    scenario: dict[str, Any],
    protocol: DecisionProtocol,
    memories: tuple[MemoryRecord, ...],
    evaluator: EvaluatorState,
    logical_time: int,
) -> tuple[CrafReferenceProtocol | None, RisiCReferenceProtocol | None, RisiCOracle | None]:
    evaluator_raw = _require_object(scenario["evaluator_only"], "evaluator_only")
    risi_c_oracle = (
        None
        if "risi_c_oracle" not in evaluator_raw
        else _parse_risi_c_oracle(evaluator_raw["risi_c_oracle"])
    )
    craf_reference = (
        None
        if "craf_reference" not in scenario
        else _parse_craf_reference(scenario["craf_reference"])
    )
    if craf_reference is not None:
        if not isinstance(protocol, ReferenceRunProtocol):
            raise OperatorInputError("craf_reference requires an approval decision protocol")
        _validate_craf_reference(
            craf_reference,
            protocol,
            memories,
            evaluator,
            logical_time,
        )
    risi_c_reference = (
        None
        if "risi_c_reference" not in scenario
        else _parse_risi_c_reference(scenario["risi_c_reference"])
    )
    if (risi_c_reference is None) != (risi_c_oracle is None):
        raise OperatorInputError("RISI-C protocol and evaluator oracle must appear together")
    if risi_c_reference is not None and risi_c_oracle is not None:
        _validate_risi_c_reference(
            risi_c_reference,
            protocol,
            memories,
            risi_c_oracle,
            logical_time,
        )
    return craf_reference, risi_c_reference, risi_c_oracle


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
    _exact_keys(
        scenario,
        required,
        "scenario",
        {"craf_reference", "risi", "risi_c_reference"},
    )
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
    _validate_decision_protocol(protocol, memory_ids, facts)
    episode_id = f"{run_id}-episode-0001"
    evaluator = _parse_evaluator(scenario["evaluator_only"], episode_id, memories, world_state)
    craf_reference, risi_c_reference, risi_c_oracle = _parse_reference_contracts(
        scenario,
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
        risi_c_reference=risi_c_reference,
        risi_c_oracle=risi_c_oracle,
        seeds=seeds,
    )
