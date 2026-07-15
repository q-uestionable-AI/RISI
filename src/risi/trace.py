"""Tamper-evident event creation and verification."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from risi.canonical import (
    JsonValue,
    canonical_sha256,
    is_sha256_digest,
    normalize_json_object,
)
from risi.models import EventVisibility, StateSnapshot, TraceEvent, TraceEventDraft

_EVALUATOR_ONLY_KEYS = frozenset(
    {
        "attack_assignment",
        "decision_oracle",
        "evaluator_only",
        "expected_outcome",
        "memory_oracles",
        "oracle_applicability",
        "oracle_criticality",
        "oracle_truth",
    }
)


class TraceIntegrityError(ValueError):
    """Raised when an event or event chain fails integrity validation."""


class VisibilityViolationError(ValueError):
    """Raised when evaluator-only data enters an attacker-visible event."""


def state_snapshot_hash(snapshot: StateSnapshot) -> str:
    """Return the canonical SHA-256 digest of a full state snapshot.

    Args:
        snapshot: Complete deterministic target-state snapshot.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """
    return canonical_sha256(snapshot.to_json())


def _require_hash(value: str, field_name: str) -> None:
    if not is_sha256_digest(value):
        raise TraceIntegrityError(f"{field_name} must be a lowercase SHA-256 digest")


def _contains_evaluator_only_key(value: JsonValue) -> bool:
    if isinstance(value, Mapping):
        return any(
            key.casefold() in _EVALUATOR_ONLY_KEYS or _contains_evaluator_only_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_evaluator_only_key(item) for item in value)
    return False


def _require_visibility_boundary(event: TraceEvent | TraceEventDraft) -> None:
    if event.visibility in {EventVisibility.ATTACKER, EventVisibility.BOTH} and (
        _contains_evaluator_only_key(event.payload)
    ):
        raise VisibilityViolationError("attacker-visible event contains evaluator-only fields")


def _event_material(
    event: TraceEvent | TraceEventDraft,
    previous_event_hash: str | None,
) -> dict[str, JsonValue]:
    return {
        "event_id": event.event_id,
        "episode_id": event.episode_id,
        "sequence": event.sequence,
        "logical_time": event.logical_time,
        "event_type": event.event_type.value,
        "actor_principal_id": event.actor_principal_id,
        "visibility": event.visibility.value,
        "state_hash_before": event.state_hash_before,
        "state_hash_after": event.state_hash_after,
        "previous_event_hash": previous_event_hash,
        "payload": normalize_json_object(event.payload),
    }


def create_event(
    draft: TraceEventDraft,
    previous_event_hash: str | None,
) -> TraceEvent:
    """Create a validated event and assign its canonical chain hash.

    Args:
        draft: Event material excluding hash-chain fields.
        previous_event_hash: Previous event digest, or ``None`` for genesis.

    Returns:
        A complete tamper-evident event.

    Raises:
        TraceIntegrityError: If a supplied state or previous-event hash is malformed.
        VisibilityViolationError: If attacker-visible payload contains evaluator-only fields.
    """
    _require_hash(draft.state_hash_before, "state_hash_before")
    _require_hash(draft.state_hash_after, "state_hash_after")
    if previous_event_hash is not None:
        _require_hash(previous_event_hash, "previous_event_hash")
    _require_visibility_boundary(draft)
    material = _event_material(draft, previous_event_hash)
    return TraceEvent(
        event_id=draft.event_id,
        episode_id=draft.episode_id,
        sequence=draft.sequence,
        logical_time=draft.logical_time,
        event_type=draft.event_type,
        actor_principal_id=draft.actor_principal_id,
        visibility=draft.visibility,
        state_hash_before=draft.state_hash_before,
        state_hash_after=draft.state_hash_after,
        previous_event_hash=previous_event_hash,
        event_hash=canonical_sha256(material),
        payload=draft.payload,
    )


def event_to_json(event: TraceEvent) -> dict[str, JsonValue]:
    """Return the canonical JSON-compatible event representation.

    Args:
        event: Complete trace event.

    Returns:
        Event object including its event hash.
    """
    material = _event_material(event, event.previous_event_hash)
    material["event_hash"] = event.event_hash
    return material


def _verify_event(
    event: TraceEvent,
    expected_episode: str,
    expected_sequence: int,
    previous: TraceEvent | None,
    event_ids: set[str],
) -> None:
    _require_hash(event.state_hash_before, "state_hash_before")
    _require_hash(event.state_hash_after, "state_hash_after")
    _require_hash(event.event_hash, "event_hash")
    if event.episode_id != expected_episode:
        raise TraceIntegrityError("all events must belong to one episode")
    if event.sequence != expected_sequence:
        raise TraceIntegrityError("event sequence must be contiguous and zero-based")
    if event.event_id in event_ids:
        raise TraceIntegrityError("event IDs must be unique")
    event_ids.add(event.event_id)

    expected_previous_hash = previous.event_hash if previous is not None else None
    if event.previous_event_hash != expected_previous_hash:
        raise TraceIntegrityError("previous event hash does not match the chain")
    if previous is not None and event.logical_time < previous.logical_time:
        raise TraceIntegrityError("logical time must not decrease")
    if previous is not None and event.state_hash_before != previous.state_hash_after:
        raise TraceIntegrityError("adjacent event state hashes are discontinuous")

    _require_visibility_boundary(event)
    expected_hash = canonical_sha256(_event_material(event, expected_previous_hash))
    if event.event_hash != expected_hash:
        raise TraceIntegrityError("event hash does not match canonical event material")


def verify_trace(events: Iterable[TraceEvent]) -> None:
    """Verify sequence, state continuity, visibility, and every event hash.

    Args:
        events: Ordered events from one deterministic episode.

    Raises:
        TraceIntegrityError: If the chain is malformed, discontinuous, or has been modified.
        VisibilityViolationError: If an attacker-visible event contains evaluator-only fields.
    """
    ordered_events = tuple(events)
    if not ordered_events:
        return

    expected_episode = ordered_events[0].episode_id
    previous: TraceEvent | None = None
    event_ids: set[str] = set()
    for expected_sequence, event in enumerate(ordered_events):
        _verify_event(event, expected_episode, expected_sequence, previous, event_ids)
        previous = event
