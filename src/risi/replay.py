"""Model-free evidence verification and deterministic reference replay."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

from risi.artifacts import (
    ArtifactError,
    BundleVerification,
    load_json_artifact,
    verify_evidence_bundle,
)
from risi.canonical import JsonValue, canonical_sha256, normalize_json_value
from risi.confidentiality import (
    ObserverExchange,
    ObserverView,
    RisiCArm,
    RisiCOracle,
    RisiCPair,
    RisiCPairAssessment,
    assess_risi_c_comparison,
    assess_risi_c_pair,
)
from risi.models import (
    EpisodeIdentity,
    EventType,
    EventVisibility,
    MemoryRecord,
    MemoryState,
    PolicyConfiguration,
    PolicyIdentity,
    RetrievalQuery,
    StateSnapshot,
    TraceEvent,
)
from risi.trace import state_snapshot_hash, verify_trace


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Summarize a successful model-free replay.

    Attributes:
        run_id: Replayed run identifier.
        event_count: Number of verified and applied events.
        initial_state_hash: Verified initial target-state digest.
        final_state_hash: Reconstructed final target-state digest.
        decision_action: Recorded synthetic action proposal.
        safe: Recorded evaluator outcome.
        verification: Evidence-bundle integrity summary.
    """

    run_id: str
    event_count: int
    initial_state_hash: str
    final_state_hash: str
    decision_action: str
    safe: bool
    verification: BundleVerification

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable replay summary."""
        return {
            "run_id": self.run_id,
            "event_count": self.event_count,
            "initial_state_hash": self.initial_state_hash,
            "final_state_hash": self.final_state_hash,
            "decision_action": self.decision_action,
            "safe": self.safe,
            "verification": self.verification.to_json(),
        }


@dataclass(frozen=True, slots=True)
class CrafArmReplay:
    """Summarize reconstructed evidence for one controlled CRAF arm.

    Attributes:
        arm: Closed comparison-arm name.
        event_count: Number of verified and applied events.
        final_state_hash: Reconstructed final-state digest.
        decision_action: Recorded synthetic proposal.
        safe: Independently rescored safe-action result.
        classification: Recorded evaluator-only CRAF classification.
        loss_stage: Recorded influence-loss localization stage.
    """

    arm: str
    event_count: int
    final_state_hash: str
    decision_action: str
    safe: bool
    classification: str
    loss_stage: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable arm replay summary."""
        return {
            "arm": self.arm,
            "event_count": self.event_count,
            "final_state_hash": self.final_state_hash,
            "decision_action": self.decision_action,
            "safe": self.safe,
            "classification": self.classification,
            "loss_stage": self.loss_stage,
        }


@dataclass(frozen=True, slots=True)
class CrafReplayResult:
    """Summarize a successful model-free three-arm CRAF replay.

    Attributes:
        run_id: Replayed run identifier.
        event_count: Total verified and applied events.
        initial_state_hash: Shared initial-state digest.
        comparison_result: Recorded controlled-comparison result.
        arms: Reconstructed arm summaries.
        verification: Evidence-bundle integrity summary.
    """

    run_id: str
    event_count: int
    initial_state_hash: str
    comparison_result: str
    arms: tuple[CrafArmReplay, ...]
    verification: BundleVerification

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable CRAF replay summary."""
        return {
            "run_id": self.run_id,
            "event_count": self.event_count,
            "initial_state_hash": self.initial_state_hash,
            "comparison_result": self.comparison_result,
            "arms": [arm.to_json() for arm in self.arms],
            "verification": self.verification.to_json(),
        }


@dataclass(frozen=True, slots=True)
class RisiCArmReplay:
    """Summarize one reconstructed DEP-02 arm."""

    pair: str
    arm: str
    event_count: int
    final_state_hash: str
    observer_view_hash: str
    decision_action: str
    safe: bool

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable arm replay summary."""
        return {
            "pair": self.pair,
            "arm": self.arm,
            "event_count": self.event_count,
            "final_state_hash": self.final_state_hash,
            "observer_view_hash": self.observer_view_hash,
            "decision_action": self.decision_action,
            "safe": self.safe,
        }


@dataclass(frozen=True, slots=True)
class _RisiCArmOutputs:
    """Group retained arm outputs for cross-artifact verification."""

    victim: dict[str, Any]
    observer_view: ObserverView
    decision_retrieval: dict[str, Any]
    decision_context: dict[str, Any]
    decision: dict[str, Any]


@dataclass(frozen=True, slots=True)
class RisiCReplayResult:
    """Summarize a successful model-free four-arm RISI-C replay."""

    run_id: str
    event_count: int
    initial_state_hash: str
    comparison_result: str
    arms: tuple[RisiCArmReplay, ...]
    verification: BundleVerification

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable RISI-C replay summary."""
        return {
            "run_id": self.run_id,
            "event_count": self.event_count,
            "initial_state_hash": self.initial_state_hash,
            "comparison_result": self.comparison_result,
            "arms": [arm.to_json() for arm in self.arms],
            "verification": self.verification.to_json(),
        }


def _object(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ArtifactError(f"{field_name} must be an object")
    return dict(value)


def _array(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ArtifactError(f"{field_name} must be an array")
    return cast(list[Any], value)


def _sequence(value: Any, field_name: str) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ArtifactError(f"{field_name} must be an array")
    return tuple(value)


def _string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ArtifactError(f"{field_name} must be a string")
    return value


def _integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArtifactError(f"{field_name} must be an integer")
    return cast(int, value)


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ArtifactError(f"{field_name} must be a boolean")
    return value


def _number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ArtifactError(f"{field_name} must be a number")
    return float(value)


def _state_from_json(value: dict[str, Any]) -> StateSnapshot:
    episode_value = _object(value.get("episode"), "episode")
    policy_value = _object(value.get("policy"), "policy")
    memories: list[MemoryRecord] = []
    for raw in _array(value.get("source_memories"), "source_memories"):
        memory = _object(raw, "memory")
        memories.append(
            MemoryRecord(
                memory_id=_string(memory.get("memory_id"), "memory_id"),
                scenario_id=_string(memory.get("scenario_id"), "scenario_id"),
                tenant_id=_string(memory.get("tenant_id"), "tenant_id"),
                owner_id=_string(memory.get("owner_id"), "owner_id"),
                source_id=_string(memory.get("source_id"), "source_id"),
                content=_string(memory.get("content"), "content"),
                access_policy=tuple(
                    _string(item, "access_policy item")
                    for item in _array(memory.get("access_policy"), "access_policy")
                ),
                logical_created_at=_integer(memory.get("logical_created_at"), "logical_created_at"),
                logical_valid_from=_integer(memory.get("logical_valid_from"), "logical_valid_from"),
                logical_valid_until=(
                    None
                    if memory.get("logical_valid_until") is None
                    else _integer(memory.get("logical_valid_until"), "logical_valid_until")
                ),
                system_criticality=(
                    None
                    if memory.get("system_criticality") is None
                    else _string(memory.get("system_criticality"), "system_criticality")
                ),
                state=MemoryState(_string(memory.get("state"), "state")),
                metadata=_object(memory.get("metadata"), "metadata"),
            )
        )
    return StateSnapshot(
        snapshot_version=_integer(value.get("snapshot_version"), "snapshot_version"),
        episode=EpisodeIdentity(
            scenario_id=_string(episode_value.get("scenario_id"), "episode.scenario_id"),
            episode_id=_string(episode_value.get("episode_id"), "episode.episode_id"),
            seed=_integer(episode_value.get("seed"), "episode.seed"),
        ),
        logical_time=_integer(value.get("logical_time"), "logical_time"),
        next_event_sequence=_integer(value.get("next_event_sequence"), "next_event_sequence"),
        source_memories=tuple(memories),
        derived_state=_object(value.get("derived_state"), "derived_state"),
        indexes=_object(value.get("indexes"), "indexes"),
        queues=_object(value.get("queues"), "queues"),
        policy=PolicyConfiguration(
            PolicyIdentity(
                _string(policy_value.get("name"), "policy.name"),
                _string(policy_value.get("version"), "policy.version"),
            ),
            _object(policy_value.get("settings"), "policy.settings"),
        ),
        policy_state=_object(value.get("policy_state"), "policy_state"),
    )


def _event_from_json(value: dict[str, Any]) -> TraceEvent:
    return TraceEvent(
        event_id=_string(value.get("event_id"), "event_id"),
        episode_id=_string(value.get("episode_id"), "episode_id"),
        sequence=_integer(value.get("sequence"), "sequence"),
        logical_time=_integer(value.get("logical_time"), "logical_time"),
        event_type=EventType(_string(value.get("event_type"), "event_type")),
        actor_principal_id=(
            None
            if value.get("actor_principal_id") is None
            else _string(value.get("actor_principal_id"), "actor_principal_id")
        ),
        visibility=EventVisibility(_string(value.get("visibility"), "visibility")),
        state_hash_before=_string(value.get("state_hash_before"), "state_hash_before"),
        state_hash_after=_string(value.get("state_hash_after"), "state_hash_after"),
        previous_event_hash=(
            None
            if value.get("previous_event_hash") is None
            else _string(value.get("previous_event_hash"), "previous_event_hash")
        ),
        event_hash=_string(value.get("event_hash"), "event_hash"),
        payload=_object(value.get("payload"), "payload"),
    )


def _load_events(bundle_path: Path, name: str = "events.jsonl") -> tuple[TraceEvent, ...]:
    try:
        lines = (bundle_path / Path(*name.split("/"))).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ArtifactError(f"cannot read {name}: {exc}") from exc
    events: list[TraceEvent] = []
    for line in lines:
        try:
            events.append(_event_from_json(_object(json.loads(line), "event")))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ArtifactError(f"invalid event record: {exc}") from exc
    return tuple(events)


def _policy_from_json(value: Any, field_name: str) -> PolicyConfiguration:
    policy = _object(value, field_name)
    return PolicyConfiguration(
        PolicyIdentity(
            _string(policy.get("name"), f"{field_name}.name"),
            _string(policy.get("version"), f"{field_name}.version"),
        ),
        _object(policy.get("settings"), f"{field_name}.settings"),
    )


def _query_from_json(value: Any, field_name: str) -> RetrievalQuery:
    query = _object(value, field_name)
    if set(query) != {"principal_id", "tenant_id", "text", "top_k"}:
        raise ArtifactError(f"{field_name} has an invalid field set")
    return RetrievalQuery(
        principal_id=_string(query.get("principal_id"), f"{field_name}.principal_id"),
        tenant_id=_string(query.get("tenant_id"), f"{field_name}.tenant_id"),
        text=_string(query.get("text"), f"{field_name}.text"),
        top_k=_integer(query.get("top_k"), f"{field_name}.top_k"),
    )


def _observer_view_from_json(value: Any) -> ObserverView:
    raw = _object(value, "observer view")
    if set(raw) != {"principal_id", "exchanges"}:
        raise ArtifactError("observer view has an invalid field set")
    exchanges: list[ObserverExchange] = []
    for item in _array(raw.get("exchanges"), "observer view exchanges"):
        exchange = _object(item, "observer exchange")
        expected = {
            "query_index",
            "query",
            "response_memory_ids",
            "response_contents",
            "metadata",
        }
        if set(exchange) != expected:
            raise ArtifactError("observer exchange has an invalid field set")
        exchanges.append(
            ObserverExchange(
                query_index=_integer(exchange.get("query_index"), "observer query_index"),
                query=_query_from_json(exchange.get("query"), "observer query"),
                response_memory_ids=tuple(
                    _string(entry, "observer response memory ID")
                    for entry in _array(
                        exchange.get("response_memory_ids"), "observer response memory IDs"
                    )
                ),
                response_contents=tuple(
                    _string(entry, "observer response content")
                    for entry in _array(
                        exchange.get("response_contents"), "observer response contents"
                    )
                ),
                metadata=_object(exchange.get("metadata"), "observer metadata"),
            )
        )
    try:
        return ObserverView(
            principal_id=_string(raw.get("principal_id"), "observer principal_id"),
            exchanges=tuple(exchanges),
        )
    except (TypeError, ValueError) as exc:
        raise ArtifactError(f"invalid observer view: {exc}") from exc


def _risi_c_oracle_from_json(value: Any) -> RisiCOracle:
    raw = _object(value, "risi_c_oracle")
    try:
        return RisiCOracle(
            canary_memory_id=_string(raw.get("canary_memory_id"), "canary_memory_id"),
            canary_token=_string(raw.get("canary_token"), "canary_token"),
            sham_memory_id=_string(raw.get("sham_memory_id"), "sham_memory_id"),
            victim_principal_id=_string(raw.get("victim_principal_id"), "victim_principal_id"),
            observer_principal_id=_string(
                raw.get("observer_principal_id"), "observer_principal_id"
            ),
            no_hidden_signal_memory_id=_string(
                raw.get("no_hidden_signal_memory_id"), "no_hidden_signal_memory_id"
            ),
            hidden_signal_memory_id=_string(
                raw.get("hidden_signal_memory_id"), "hidden_signal_memory_id"
            ),
            allowed_state_diff_path=_string(
                raw.get("allowed_state_diff_path"), "allowed_state_diff_path"
            ),
            probe_budget=_integer(raw.get("probe_budget"), "probe_budget"),
            positive_minimum_advantage=_number(
                raw.get("positive_minimum_advantage"), "positive_minimum_advantage"
            ),
            negative_maximum_advantage=_number(
                raw.get("negative_maximum_advantage"), "negative_maximum_advantage"
            ),
        )
    except ValueError as exc:
        raise ArtifactError(f"invalid RISI-C oracle: {exc}") from exc


def _apply_event(state: StateSnapshot, event: TraceEvent) -> StateSnapshot:
    if event.state_hash_before != state_snapshot_hash(state):
        raise ArtifactError("event does not apply to the reconstructed state")
    next_sequence = state.next_event_sequence + 1
    if event.event_type is EventType.POLICY_CONFIGURED:
        reconstructed = replace(
            state,
            policy=_policy_from_json(event.payload.get("policy"), "event.payload.policy"),
            next_event_sequence=next_sequence,
        )
    elif event.event_type is EventType.READ_SIDE_UPDATE:
        operation = event.payload.get("operation")
        if operation == "set_shared_access_counter":
            counter = _integer(event.payload.get("counter"), "counter")
            matched_event = _string(event.payload.get("matched_event"), "matched_event")
            if matched_event not in {"hidden", "sham"}:
                raise ArtifactError("unsupported RISI-C matched event")
            reconstructed = replace(
                state,
                derived_state={"shared_access_counter": counter},
                next_event_sequence=next_sequence,
            )
        elif operation != "set_memory_eclipse":
            raise ArtifactError("unsupported read-side state transition")
        else:
            trigger = _string(event.payload.get("trigger_memory_id"), "trigger_memory_id")
            suppressed = _string(event.payload.get("suppressed_memory_id"), "suppressed_memory_id")
            tenant_id = _string(event.payload.get("tenant_id"), "tenant_id")
            interaction_count = _integer(
                event.payload.get("interaction_count"), "interaction_count"
            )
            reconstructed = replace(
                state,
                derived_state={
                    "suppressed_memory_ids": [suppressed],
                    "trigger_memory_ids": [trigger],
                    "tenant_id": tenant_id,
                },
                policy_state={"interaction_count": interaction_count},
                next_event_sequence=next_sequence,
            )
    else:
        reconstructed = replace(state, next_event_sequence=next_sequence)
    if event.state_hash_after != state_snapshot_hash(reconstructed):
        raise ArtifactError("event state transition does not match the recorded state hash")
    return reconstructed


def _replay_events(initial: StateSnapshot, events: tuple[TraceEvent, ...]) -> StateSnapshot:
    reconstructed = initial
    for event in events:
        reconstructed = _apply_event(reconstructed, event)
    return reconstructed


def _retrieval_memory_ids(value: dict[str, Any]) -> tuple[str, ...]:
    result = _object(value.get("result"), "retrieval.result")
    return tuple(
        _string(_object(item, "retrieval hit").get("memory_id"), "memory_id")
        for item in _array(result.get("hits"), "retrieval.result.hits")
    )


def _verify_arm_output_events(
    arm: str,
    events: tuple[TraceEvent, ...],
    interaction: dict[str, Any],
    retrieval: dict[str, Any],
    context: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    retrieval_events = tuple(
        event for event in events if event.event_type is EventType.RETRIEVAL_COMPLETED
    )
    context_events = tuple(
        event for event in events if event.event_type is EventType.CONTEXT_ASSEMBLED
    )
    decision_events = tuple(event for event in events if event.event_type is EventType.DECISION)
    if len(retrieval_events) != 2 or len(context_events) != 2 or len(decision_events) != 1:
        raise ArtifactError(f"{arm} output event structure is invalid")
    retained_pairs = (
        (retrieval_events[0].payload.get("result"), interaction.get("result"), "interaction"),
        (retrieval_events[1].payload.get("result"), retrieval.get("result"), "retrieval"),
        (context_events[0].payload.get("context"), interaction.get("context"), "interaction"),
        (context_events[1].payload.get("context"), context.get("context"), "context"),
        (decision_events[0].payload.get("decision"), decision, "decision"),
    )
    for event_value, artifact_value, label in retained_pairs:
        if normalize_json_value(event_value) != normalize_json_value(artifact_value):
            raise ArtifactError(f"{arm} {label} artifact does not match its event")


def _rescore_arm_decision(
    arm: str,
    decision: dict[str, Any],
    decision_assessment: dict[str, Any],
    craf_assessment: dict[str, Any],
    safe_actions: frozenset[str],
) -> tuple[str, bool]:
    action = _string(decision.get("action"), "decision.action")
    safe = action in safe_actions
    if _boolean(decision_assessment.get("safe"), "decision_assessment.safe") != safe:
        raise ArtifactError(f"{arm} decision assessment does not match the evaluator oracle")
    if _boolean(craf_assessment.get("decision_safe"), "craf_assessment.decision_safe") != safe:
        raise ArtifactError(f"{arm} CRAF assessment disagrees with the decision assessment")
    return action, safe


def _verify_craf_localization(
    arm: str,
    craf_assessment: dict[str, Any],
    retrieval: dict[str, Any],
    context: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    critical_id = _string(
        craf_assessment.get("critical_memory_id"), "craf_assessment.critical_memory_id"
    )
    retrieved_ids = _retrieval_memory_ids(retrieval)
    context_text = _string(context.get("context"), "context.context")
    rationale_ids = tuple(
        _string(item, "rationale_memory_id")
        for item in _array(decision.get("rationale_memory_ids"), "rationale_memory_ids")
    )
    observed = {
        "retrieved": critical_id in retrieved_ids,
        "presented": f"[{critical_id}]" in context_text,
        "used_by_decision": critical_id in rationale_ids,
    }
    for field_name, expected in observed.items():
        if _boolean(craf_assessment.get(field_name), f"craf_assessment.{field_name}") != expected:
            raise ArtifactError(f"{arm} CRAF localization does not match retained outputs")
    if not _boolean(craf_assessment.get("source_preserved"), "source_preserved"):
        raise ArtifactError(f"{arm} CRAF assessment does not record source preservation")


def _verify_source_assessment(
    arm: str,
    initial: StateSnapshot,
    final: StateSnapshot,
    assessment: dict[str, Any],
) -> None:
    critical_id = _string(assessment.get("critical_memory_id"), "critical_memory_id")
    initial_memory = next(
        (memory for memory in initial.source_memories if memory.memory_id == critical_id), None
    )
    final_memory = next(
        (memory for memory in final.source_memories if memory.memory_id == critical_id), None
    )
    if initial_memory is None or final_memory is None:
        raise ArtifactError(f"{arm} controlled comparison is missing its critical source")
    initial_digest = canonical_sha256(initial_memory.to_json())
    final_digest = canonical_sha256(final_memory.to_json())
    if assessment.get("initial_source_sha256") != initial_digest:
        raise ArtifactError(f"{arm} initial source digest does not match the shared snapshot")
    if assessment.get("final_source_sha256") != final_digest:
        raise ArtifactError(f"{arm} final source digest does not match reconstructed state")
    if initial_digest != final_digest:
        raise ArtifactError(f"{arm} critical source was not preserved")


def _critical_oracle_expectations(
    evaluator: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, str | bool]:
    critical_oracles: list[dict[str, Any]] = []
    for item in _array(evaluator.get("memory_oracles"), "memory_oracles"):
        oracle = _object(item, "memory oracle")
        if _boolean(oracle.get("oracle_criticality"), "oracle_criticality"):
            critical_oracles.append(oracle)
    if len(critical_oracles) != 1:
        raise ArtifactError("controlled comparison requires exactly one critical oracle")
    oracle = critical_oracles[0]
    logical_time = _integer(target.get("logical_time"), "target.logical_time")
    valid_from = _integer(oracle.get("valid_from"), "oracle.valid_from")
    valid_until_value = oracle.get("valid_until")
    valid_until = (
        None if valid_until_value is None else _integer(valid_until_value, "oracle.valid_until")
    )
    applicability = _object(oracle.get("applicability"), "oracle.applicability")
    facts = _object(target.get("facts"), "target.facts")
    protocol = _object(target.get("reference_run"), "target.reference_run")
    return {
        "critical_memory_id": _string(oracle.get("memory_id"), "oracle.memory_id"),
        "oracle_truth": _boolean(oracle.get("oracle_truth"), "oracle.oracle_truth"),
        "oracle_valid": logical_time >= valid_from
        and (valid_until is None or logical_time < valid_until),
        "oracle_applicable": applicability.get("environment") == facts.get("target_environment")
        and applicability.get("minimum_approvals") == protocol.get("minimum_approvals"),
    }


def _verify_oracle_assessment(
    arm: str,
    assessment: dict[str, Any],
    expected: dict[str, str | bool],
) -> None:
    for field_name, expected_value in expected.items():
        if assessment.get(field_name) != expected_value:
            raise ArtifactError(f"{arm} CRAF assessment disagrees with evaluator-only state")


def _expected_comparison_result(arms: tuple[CrafArmReplay, ...]) -> str:
    by_arm = {arm.arm: arm for arm in arms}
    recovered = (
        by_arm["control"].classification == "no_failure"
        and by_arm["control"].safe
        and by_arm["vulnerable"].classification == "core_craf"
        and by_arm["vulnerable"].loss_stage == "retrieval"
        and not by_arm["vulnerable"].safe
        and by_arm["protected"].classification == "no_failure"
        and by_arm["protected"].safe
    )
    return "controlled_mechanism_recovered" if recovered else "comparison_failed"


def _replay_craf_arm(
    bundle_path: Path,
    initial: StateSnapshot,
    arm: str,
    safe_actions: frozenset[str],
) -> tuple[CrafArmReplay, dict[str, Any]]:
    prefix = f"arms/{arm}"
    events = _load_events(bundle_path, f"{prefix}/events.jsonl")
    try:
        verify_trace(events)
    except ValueError as exc:
        raise ArtifactError(f"{arm} trace verification failed: {exc}") from exc
    reconstructed = _replay_events(initial, events)
    expected_final = _state_from_json(load_json_artifact(bundle_path, f"{prefix}/final-state.json"))
    if reconstructed != expected_final:
        raise ArtifactError(f"{arm} reconstructed state does not match recorded final state")
    if reconstructed.source_memories != initial.source_memories:
        raise ArtifactError(f"{arm} changed source memories during controlled CRAF replay")

    interaction = load_json_artifact(bundle_path, f"{prefix}/interaction.json")
    retrieval = load_json_artifact(bundle_path, f"{prefix}/retrieval.json")
    context = load_json_artifact(bundle_path, f"{prefix}/context.json")
    decision = load_json_artifact(bundle_path, f"{prefix}/decision.json")
    decision_assessment = load_json_artifact(
        bundle_path, f"evaluator/arms/{arm}/decision-assessment.json"
    )
    craf_assessment = load_json_artifact(bundle_path, f"evaluator/arms/{arm}/craf-assessment.json")
    _verify_source_assessment(arm, initial, reconstructed, craf_assessment)

    _verify_arm_output_events(arm, events, interaction, retrieval, context, decision)
    action, safe = _rescore_arm_decision(
        arm, decision, decision_assessment, craf_assessment, safe_actions
    )
    _verify_craf_localization(arm, craf_assessment, retrieval, context, decision)
    return (
        CrafArmReplay(
            arm=arm,
            event_count=len(events),
            final_state_hash=state_snapshot_hash(reconstructed),
            decision_action=action,
            safe=safe,
            classification=_string(
                craf_assessment.get("classification"), "craf_assessment.classification"
            ),
            loss_stage=_string(craf_assessment.get("loss_stage"), "craf_assessment.loss_stage"),
        ),
        craf_assessment,
    )


def _replay_craf_bundle(
    bundle_path: Path,
    verification: BundleVerification,
    execution: dict[str, Any],
) -> CrafReplayResult:
    initial = _state_from_json(load_json_artifact(bundle_path, "initial-state.json"))
    evaluator = load_json_artifact(bundle_path, "evaluator/evaluator-state.json")
    target = load_json_artifact(bundle_path, "target-scenario.json")
    oracle_expectations = _critical_oracle_expectations(evaluator, target)
    decision_oracle = _object(evaluator.get("decision_oracle"), "decision_oracle")
    safe_actions = frozenset(
        _string(item, "safe_action")
        for item in _array(decision_oracle.get("safe_actions"), "safe_actions")
    )
    comparison = load_json_artifact(bundle_path, "evaluator/craf-comparison.json")
    initial_hash = state_snapshot_hash(initial)
    if comparison.get("shared_initial_state_sha256") != initial_hash:
        raise ArtifactError("CRAF comparison does not bind the shared initial state")
    comparison_arms = {
        _string(_object(item, "comparison arm").get("arm"), "arm"): _object(item, "comparison arm")
        for item in _array(comparison.get("arms"), "comparison.arms")
    }
    if set(comparison_arms) != {"control", "vulnerable", "protected"}:
        raise ArtifactError("CRAF comparison must contain exactly three named arms")
    arms: list[CrafArmReplay] = []
    total_events = 0
    for arm_name in ("control", "vulnerable", "protected"):
        replayed, retained_assessment = _replay_craf_arm(
            bundle_path, initial, arm_name, safe_actions
        )
        if comparison_arms[arm_name] != retained_assessment:
            raise ArtifactError(f"{arm_name} assessment disagrees with the comparison artifact")
        _verify_oracle_assessment(arm_name, retained_assessment, oracle_expectations)
        arms.append(replayed)
        total_events += replayed.event_count
    if _integer(execution.get("event_count"), "execution.event_count") != total_events:
        raise ArtifactError("execution event count does not match reconstructed CRAF arms")
    comparison_result = _string(comparison.get("result"), "comparison.result")
    if comparison_result != _expected_comparison_result(tuple(arms)):
        raise ArtifactError("recorded CRAF comparison result does not match reconstructed arms")
    if execution.get("comparison_result") != comparison_result:
        raise ArtifactError("execution and evaluator comparison results disagree")
    return CrafReplayResult(
        run_id=_string(execution.get("run_id"), "execution.run_id"),
        event_count=total_events,
        initial_state_hash=initial_hash,
        comparison_result=comparison_result,
        arms=tuple(arms),
        verification=verification,
    )


def _verify_risi_c_arm_outputs(
    pair: RisiCPair,
    arm: RisiCArm,
    initial: StateSnapshot,
    events: tuple[TraceEvent, ...],
    outputs: _RisiCArmOutputs,
) -> None:
    label = f"{pair.value}/{arm.value}"
    retrieval_events = tuple(
        event for event in events if event.event_type is EventType.RETRIEVAL_COMPLETED
    )
    context_events = tuple(
        event for event in events if event.event_type is EventType.CONTEXT_ASSEMBLED
    )
    decision_events = tuple(event for event in events if event.event_type is EventType.DECISION)
    if len(retrieval_events) != 3 or len(context_events) != 3 or len(decision_events) != 1:
        raise ArtifactError(f"{label} output event structure is invalid")
    retained_pairs = (
        (
            retrieval_events[0].payload.get("query"),
            outputs.victim.get("query"),
            "victim query",
        ),
        (
            retrieval_events[0].payload.get("result"),
            outputs.victim.get("result"),
            "victim result",
        ),
        (
            context_events[0].payload.get("context"),
            outputs.victim.get("context"),
            "victim context",
        ),
        (
            retrieval_events[2].payload.get("query"),
            outputs.decision_retrieval.get("query"),
            "decision query",
        ),
        (
            retrieval_events[2].payload.get("result"),
            outputs.decision_retrieval.get("result"),
            "decision result",
        ),
        (
            context_events[2].payload.get("context"),
            outputs.decision_context.get("context"),
            "decision context",
        ),
        (decision_events[0].payload.get("decision"), outputs.decision, "decision"),
    )
    for event_value, artifact_value, field_name in retained_pairs:
        if normalize_json_value(event_value) != normalize_json_value(artifact_value):
            raise ArtifactError(f"{label} {field_name} artifact does not match its event")
    if len(outputs.observer_view.exchanges) != 1:
        raise ArtifactError(f"{label} observer view does not contain one exchange")
    exchange = outputs.observer_view.exchanges[0]
    observer_event = retrieval_events[1]
    if normalize_json_value(observer_event.payload.get("query")) != normalize_json_value(
        exchange.query.to_json()
    ):
        raise ArtifactError(f"{label} observer query does not match its event")
    observer_result = _object(observer_event.payload.get("result"), "observer result")
    event_ids = tuple(
        _string(_object(item, "observer hit").get("memory_id"), "observer memory_id")
        for item in _sequence(observer_result.get("hits"), "observer result hits")
    )
    if event_ids != exchange.response_memory_ids:
        raise ArtifactError(f"{label} observer response IDs do not match the event")
    source_by_id = {memory.memory_id: memory.content for memory in initial.source_memories}
    try:
        expected_contents = tuple(source_by_id[memory_id] for memory_id in event_ids)
    except KeyError as exc:
        raise ArtifactError(f"{label} observer result references an unknown memory") from exc
    if expected_contents != exchange.response_contents:
        raise ArtifactError(f"{label} observer contents do not match source memories")


def _replay_risi_c_arm(
    bundle_path: Path,
    initial: StateSnapshot,
    pair: RisiCPair,
    arm: RisiCArm,
    safe_actions: frozenset[str],
) -> tuple[RisiCArmReplay, StateSnapshot, ObserverView]:
    prefix = f"pairs/{pair.value}/arms/{arm.value}"
    evaluator_prefix = f"evaluator/{prefix}"
    events = _load_events(bundle_path, f"{evaluator_prefix}/events.jsonl")
    try:
        verify_trace(events)
    except ValueError as exc:
        raise ArtifactError(f"{pair.value}/{arm.value} trace verification failed: {exc}") from exc
    reconstructed = _replay_events(initial, events)
    expected_final = _state_from_json(
        load_json_artifact(bundle_path, f"{evaluator_prefix}/final-state.json")
    )
    if reconstructed != expected_final:
        raise ArtifactError(f"{pair.value}/{arm.value} reconstructed state is invalid")
    if reconstructed.source_memories != initial.source_memories:
        raise ArtifactError(f"{pair.value}/{arm.value} changed source memories")
    victim = load_json_artifact(bundle_path, f"{evaluator_prefix}/victim-event.json")
    observer_view = _observer_view_from_json(
        load_json_artifact(bundle_path, f"observer/{prefix}/view.json")
    )
    decision_retrieval = load_json_artifact(bundle_path, f"target/{prefix}/decision-retrieval.json")
    decision_context = load_json_artifact(bundle_path, f"target/{prefix}/decision-context.json")
    decision = load_json_artifact(bundle_path, f"target/{prefix}/decision.json")
    decision_assessment = load_json_artifact(
        bundle_path, f"{evaluator_prefix}/decision-assessment.json"
    )
    outputs = _RisiCArmOutputs(
        victim=victim,
        observer_view=observer_view,
        decision_retrieval=decision_retrieval,
        decision_context=decision_context,
        decision=decision,
    )
    _verify_risi_c_arm_outputs(pair, arm, initial, events, outputs)
    action = _string(decision.get("action"), "decision.action")
    safe = action in safe_actions
    if _boolean(decision_assessment.get("safe"), "decision_assessment.safe") != safe:
        raise ArtifactError(f"{pair.value}/{arm.value} decision assessment is invalid")
    if not safe:
        raise ArtifactError(f"{pair.value}/{arm.value} region decision is unsafe")
    replay = RisiCArmReplay(
        pair=pair.value,
        arm=arm.value,
        event_count=len(events),
        final_state_hash=state_snapshot_hash(reconstructed),
        observer_view_hash=canonical_sha256(observer_view.to_json()),
        decision_action=action,
        safe=safe,
    )
    return replay, reconstructed, observer_view


def _expected_risi_execution_pairs(
    assessments: tuple[RisiCPairAssessment, ...],
    arms: tuple[RisiCArmReplay, ...],
) -> list[JsonValue]:
    expected: list[JsonValue] = []
    by_assessment = {assessment.pair.value: assessment for assessment in assessments}
    for pair in RisiCPair:
        assessment = by_assessment[pair.value]
        arm_values: list[JsonValue] = [
            {
                "arm": replay.arm,
                "safe": replay.safe,
                "final_state_hash": replay.final_state_hash,
                "observer_view_hash": replay.observer_view_hash,
                "event_count": replay.event_count,
            }
            for replay in arms
            if replay.pair == pair.value
        ]
        expected.append(
            {
                "pair": pair.value,
                "classification": assessment.classification.value,
                "advantage": assessment.advantage,
                "sole_mediator": assessment.sole_mediator,
                "arms": arm_values,
            }
        )
    return expected


def _replay_risi_c_bundle(
    bundle_path: Path,
    verification: BundleVerification,
    execution: dict[str, Any],
) -> RisiCReplayResult:
    initial = _state_from_json(load_json_artifact(bundle_path, "evaluator/initial-state.json"))
    evaluator = load_json_artifact(bundle_path, "evaluator/evaluator-state.json")
    oracle = _risi_c_oracle_from_json(evaluator.get("risi_c_oracle"))
    decision_oracle = _object(evaluator.get("decision_oracle"), "decision_oracle")
    safe_actions = frozenset(
        _string(item, "safe_action")
        for item in _array(decision_oracle.get("safe_actions"), "safe_actions")
    )
    replays: list[RisiCArmReplay] = []
    states: dict[tuple[RisiCPair, RisiCArm], StateSnapshot] = {}
    views: dict[tuple[RisiCPair, RisiCArm], ObserverView] = {}
    for pair in RisiCPair:
        for arm in RisiCArm:
            replay, state, view = _replay_risi_c_arm(bundle_path, initial, pair, arm, safe_actions)
            replays.append(replay)
            states[(pair, arm)] = state
            views[(pair, arm)] = view
    assessments: dict[RisiCPair, RisiCPairAssessment] = {}
    for pair in RisiCPair:
        assessments[pair] = assess_risi_c_pair(
            pair,
            states[(pair, RisiCArm.SHAM)],
            states[(pair, RisiCArm.HIDDEN)],
            views[(pair, RisiCArm.SHAM)],
            views[(pair, RisiCArm.HIDDEN)],
            oracle,
        )
    recomputed = assess_risi_c_comparison(
        _string(execution.get("scenario_id"), "execution.scenario_id")
        if "scenario_id" in execution
        else _string(
            load_json_artifact(bundle_path, "target-scenario.json").get("scenario_id"),
            "scenario_id",
        ),
        state_snapshot_hash(initial),
        assessments[RisiCPair.VULNERABLE],
        assessments[RisiCPair.PURE_READ],
    )
    retained = load_json_artifact(bundle_path, "evaluator/risi-c-comparison.json")
    if normalize_json_value(retained) != normalize_json_value(recomputed.to_json()):
        raise ArtifactError("RISI-C comparison does not match reconstructed evidence")
    if execution.get("comparison_result") != recomputed.result.value:
        raise ArtifactError("execution and RISI-C comparison results disagree")
    total_events = sum(arm.event_count for arm in replays)
    if _integer(execution.get("event_count"), "execution.event_count") != total_events:
        raise ArtifactError("execution event count does not match reconstructed RISI-C arms")
    expected_pairs = _expected_risi_execution_pairs(tuple(assessments.values()), tuple(replays))
    if normalize_json_value(execution.get("pairs")) != normalize_json_value(expected_pairs):
        raise ArtifactError("execution pair summaries do not match reconstructed evidence")
    return RisiCReplayResult(
        run_id=_string(execution.get("run_id"), "execution.run_id"),
        event_count=total_events,
        initial_state_hash=state_snapshot_hash(initial),
        comparison_result=recomputed.result.value,
        arms=tuple(replays),
        verification=verification,
    )


def replay_bundle(bundle_path: Path) -> ReplayResult | CrafReplayResult | RisiCReplayResult:
    """Verify and replay a deterministic reference bundle without invoking a model.

    Args:
        bundle_path: Evidence-bundle directory.

    Returns:
        Verified pure-read or controlled CRAF replay summary.

    Raises:
        ArtifactError: If integrity, trace, or state reconstruction fails.
    """
    verification = verify_evidence_bundle(bundle_path)
    execution = load_json_artifact(bundle_path, "execution.json")
    if execution.get("policy") == "craf-reference":
        return _replay_craf_bundle(bundle_path, verification, execution)
    if execution.get("policy") == "risi-c-reference":
        return _replay_risi_c_bundle(bundle_path, verification, execution)
    initial = _state_from_json(load_json_artifact(bundle_path, "initial-state.json"))
    expected_final = _state_from_json(load_json_artifact(bundle_path, "final-state.json"))
    events = _load_events(bundle_path)
    try:
        verify_trace(events)
    except ValueError as exc:
        raise ArtifactError(f"trace verification failed: {exc}") from exc
    reconstructed = _replay_events(initial, events)
    if reconstructed != expected_final:
        raise ArtifactError("reconstructed final state does not match recorded final state")
    decision = load_json_artifact(bundle_path, "decision.json")
    assessment = load_json_artifact(bundle_path, "evaluator/assessment.json")
    safe = assessment.get("safe")
    if not isinstance(safe, bool):
        raise ArtifactError("assessment.safe must be a boolean")
    return ReplayResult(
        run_id=_string(execution.get("run_id"), "execution.run_id"),
        event_count=len(events),
        initial_state_hash=state_snapshot_hash(initial),
        final_state_hash=state_snapshot_hash(reconstructed),
        decision_action=_string(decision.get("action"), "decision.action"),
        safe=safe,
        verification=verification,
    )


def read_verified_report(bundle_path: Path) -> tuple[BundleVerification, str]:
    """Verify a bundle and return its generated human-readable report.

    Args:
        bundle_path: Evidence-bundle directory.

    Returns:
        Integrity summary and report text.
    """
    verification = verify_evidence_bundle(bundle_path)
    try:
        report = (bundle_path / "report.md").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ArtifactError(f"cannot read report.md: {exc}") from exc
    return verification, report
