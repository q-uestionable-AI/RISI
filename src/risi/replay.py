"""Model-free evidence verification and deterministic pure-read replay."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

from risi.artifacts import (
    ArtifactError,
    BundleVerification,
    load_json_artifact,
    verify_evidence_bundle,
)
from risi.canonical import JsonValue
from risi.models import (
    EpisodeIdentity,
    EventType,
    EventVisibility,
    MemoryRecord,
    MemoryState,
    PolicyConfiguration,
    PolicyIdentity,
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


def _object(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{field_name} must be an object")
    return cast(dict[str, Any], value)


def _array(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ArtifactError(f"{field_name} must be an array")
    return cast(list[Any], value)


def _string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ArtifactError(f"{field_name} must be a string")
    return value


def _integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArtifactError(f"{field_name} must be an integer")
    return cast(int, value)


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


def _load_events(bundle_path: Path) -> tuple[TraceEvent, ...]:
    try:
        lines = (bundle_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ArtifactError(f"cannot read events.jsonl: {exc}") from exc
    events: list[TraceEvent] = []
    for line in lines:
        try:
            events.append(_event_from_json(_object(json.loads(line), "event")))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ArtifactError(f"invalid event record: {exc}") from exc
    return tuple(events)


def replay_bundle(bundle_path: Path) -> ReplayResult:
    """Verify and replay a pure-read evidence bundle without invoking a model.

    Replay version 1 applies the closed invariant that each recorded pure-read event advances only
    ``next_event_sequence``. Later state-changing policies will require explicit state patches.

    Args:
        bundle_path: Evidence-bundle directory.

    Returns:
        Verified model-free replay summary.

    Raises:
        ArtifactError: If integrity, trace, or state reconstruction fails.
    """
    verification = verify_evidence_bundle(bundle_path)
    initial = _state_from_json(load_json_artifact(bundle_path, "initial-state.json"))
    expected_final = _state_from_json(load_json_artifact(bundle_path, "final-state.json"))
    events = _load_events(bundle_path)
    try:
        verify_trace(events)
    except ValueError as exc:
        raise ArtifactError(f"trace verification failed: {exc}") from exc
    reconstructed = initial
    for event in events:
        if event.state_hash_before != state_snapshot_hash(reconstructed):
            raise ArtifactError("event does not apply to the reconstructed state")
        reconstructed = replace(
            reconstructed,
            next_event_sequence=reconstructed.next_event_sequence + 1,
        )
        if event.state_hash_after != state_snapshot_hash(reconstructed):
            raise ArtifactError("event state transition is not a pure-read replay step")
    if reconstructed != expected_final:
        raise ArtifactError("reconstructed final state does not match recorded final state")
    execution = load_json_artifact(bundle_path, "execution.json")
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
