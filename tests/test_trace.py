from dataclasses import replace

import pytest

from risi.models import EventType, EventVisibility, TraceEventDraft
from risi.trace import (
    TraceIntegrityError,
    VisibilityViolationError,
    create_event,
    event_to_json,
    verify_trace,
)

STATE_A = "a" * 64
STATE_B = "b" * 64
STATE_C = "c" * 64


def _draft(
    *,
    event_id: str,
    sequence: int,
    state_before: str,
    state_after: str,
    visibility: EventVisibility = EventVisibility.EVALUATOR,
    payload: dict[str, object] | None = None,
) -> TraceEventDraft:
    return TraceEventDraft(
        event_id=event_id,
        episode_id="episode-dep-01",
        sequence=sequence,
        logical_time=410 + sequence,
        event_type=EventType.EPISODE_STARTED,
        actor_principal_id=None,
        visibility=visibility,
        state_hash_before=state_before,
        state_hash_after=state_after,
        payload={} if payload is None else payload,  # type: ignore[arg-type]
    )


def _valid_chain() -> tuple:
    first = create_event(
        _draft(event_id="event-0", sequence=0, state_before=STATE_A, state_after=STATE_B),
        None,
    )
    second = create_event(
        _draft(event_id="event-1", sequence=1, state_before=STATE_B, state_after=STATE_C),
        first.event_hash,
    )
    return first, second


def test_trace_round_trip_verifies_canonical_hash_chain() -> None:
    first, second = _valid_chain()

    verify_trace((first, second))

    serialized = event_to_json(first)
    assert serialized["event_hash"] == first.event_hash
    assert serialized["previous_event_hash"] is None


def test_trace_detects_payload_tampering() -> None:
    first, second = _valid_chain()
    tampered = replace(first, payload={"changed": True})

    with pytest.raises(TraceIntegrityError, match="event hash"):
        verify_trace((tampered, second))


def test_trace_rejects_sequence_and_state_discontinuity() -> None:
    first, second = _valid_chain()

    with pytest.raises(TraceIntegrityError, match="sequence"):
        verify_trace((first, replace(second, sequence=3)))
    with pytest.raises(TraceIntegrityError, match="state hashes"):
        verify_trace((first, replace(second, state_hash_before=STATE_A)))


def test_attacker_visible_events_reject_evaluator_only_fields() -> None:
    draft = _draft(
        event_id="event-0",
        sequence=0,
        state_before=STATE_A,
        state_after=STATE_A,
        visibility=EventVisibility.ATTACKER,
        payload={"nested": {"memory_oracles": []}},
    )

    with pytest.raises(VisibilityViolationError, match="evaluator-only"):
        create_event(draft, None)


def test_evaluator_event_may_record_non_target_oracle_summary() -> None:
    event = create_event(
        _draft(
            event_id="event-0",
            sequence=0,
            state_before=STATE_A,
            state_after=STATE_A,
            visibility=EventVisibility.EVALUATOR,
            payload={"oracle_criticality": True},
        ),
        None,
    )

    verify_trace((event,))
