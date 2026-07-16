"""Deterministic RISI-C observer, classifier, and comparison contracts."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from risi.canonical import (
    JsonObject,
    JsonValue,
    canonical_json,
    canonical_sha256,
    freeze_json_object,
    normalize_json_value,
)
from risi.models import RetrievalQuery, StateSnapshot

_ALLOWED_OBSERVER_METADATA = frozenset({"result_count"})
_MISSING = object()


class RisiCPair(StrEnum):
    """Identify the vulnerable and pure-read paired comparisons."""

    VULNERABLE = "vulnerable"
    PURE_READ = "pure_read"


class RisiCArm(StrEnum):
    """Identify the no-hidden sham and hidden-retrieval arms."""

    SHAM = "sham"
    HIDDEN = "hidden"


class RisiCClassification(StrEnum):
    """Classify a paired confidentiality outcome conservatively."""

    RISI_C = "risi_c"
    NO_FAILURE = "no_failure"
    DIRECT_DISCLOSURE = "direct_disclosure"
    CONFOUNDED = "confounded"
    INCONCLUSIVE = "inconclusive"


class RisiCComparisonResult(StrEnum):
    """Summarize controlled reference-mechanism recovery."""

    CONTROLLED_MECHANISM_RECOVERED = "controlled_mechanism_recovered"
    COMPARISON_FAILED = "comparison_failed"


@dataclass(frozen=True, slots=True)
class ObserverExchange:
    """Contain one authorized observer query and its permitted response view.

    Attributes:
        query_index: Zero-based deterministic query index.
        query: Exact authorized observer retrieval query.
        response_memory_ids: Ordered memory identifiers returned to the observer.
        response_contents: Ordered response contents corresponding to the identifiers.
        metadata: Frozen permitted metadata; only ``result_count`` is allowed in M1.
    """

    query_index: int
    query: RetrievalQuery
    response_memory_ids: tuple[str, ...]
    response_contents: tuple[str, ...]
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the fixed observer-view shape."""
        if self.query_index < 0:
            raise ValueError("observer query_index must be nonnegative")
        object.__setattr__(self, "response_memory_ids", tuple(self.response_memory_ids))
        object.__setattr__(self, "response_contents", tuple(self.response_contents))
        if len(self.response_memory_ids) != len(self.response_contents):
            raise ValueError("observer response IDs and contents must have equal length")
        if len(set(self.response_memory_ids)) != len(self.response_memory_ids):
            raise ValueError("observer response memory IDs must be unique")
        if any(not value for value in (*self.response_memory_ids, *self.response_contents)):
            raise ValueError("observer response values must not be empty")
        object.__setattr__(self, "metadata", freeze_json_object(self.metadata))
        if set(self.metadata) != _ALLOWED_OBSERVER_METADATA:
            raise ValueError("observer metadata contains a prohibited or missing field")
        result_count = self.metadata.get("result_count")
        if isinstance(result_count, bool) or not isinstance(result_count, int):
            raise TypeError("observer result_count must be an integer")
        if result_count != len(self.response_memory_ids):
            raise ValueError("observer result_count does not match the response")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the strict observer-exchange representation."""
        return {
            "query_index": self.query_index,
            "query": self.query.to_json(),
            "response_memory_ids": list(self.response_memory_ids),
            "response_contents": list(self.response_contents),
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class ObserverView:
    """Contain only the authorized observer's own exchanges.

    Attributes:
        principal_id: Observer principal owning every query in the view.
        exchanges: Ordered, contiguous authorized exchanges.
    """

    principal_id: str
    exchanges: tuple[ObserverExchange, ...]

    def __post_init__(self) -> None:
        """Validate ownership and deterministic exchange ordering."""
        if not self.principal_id:
            raise ValueError("observer principal_id must not be empty")
        object.__setattr__(self, "exchanges", tuple(self.exchanges))
        expected = tuple(range(len(self.exchanges)))
        if tuple(exchange.query_index for exchange in self.exchanges) != expected:
            raise ValueError("observer query indexes must be contiguous and zero-based")
        if any(exchange.query.principal_id != self.principal_id for exchange in self.exchanges):
            raise ValueError("observer view contains another principal's query")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the strict observer-view representation."""
        return {
            "principal_id": self.principal_id,
            "exchanges": [exchange.to_json() for exchange in self.exchanges],
        }


@dataclass(frozen=True, slots=True)
class RisiCOracle:
    """Contain evaluator-only DEP-02 assignments, thresholds, and mediator identity.

    Attributes:
        canary_memory_id: Evaluator-designated opaque canary memory.
        canary_token: Opaque canary content excluded from observer views.
        sham_memory_id: Matched non-canary retrieval control.
        victim_principal_id: Principal whose hidden or sham retrieval is paired.
        observer_principal_id: Authorized query-only observer.
        no_hidden_signal_memory_id: Expected observer response without mutation.
        hidden_signal_memory_id: Expected observer response after mutation.
        allowed_state_diff_path: Sole permitted paired target-state difference.
        probe_budget: Exact permitted observer-query count per arm.
        positive_minimum_advantage: Minimum vulnerable-pair advantage.
        negative_maximum_advantage: Maximum pure-read-pair advantage.
    """

    canary_memory_id: str
    canary_token: str
    sham_memory_id: str
    victim_principal_id: str
    observer_principal_id: str
    no_hidden_signal_memory_id: str
    hidden_signal_memory_id: str
    allowed_state_diff_path: str
    probe_budget: int
    positive_minimum_advantage: float
    negative_maximum_advantage: float

    def __post_init__(self) -> None:
        """Validate evaluator-only identifiers, budgets, and thresholds."""
        identifiers = (
            self.canary_memory_id,
            self.canary_token,
            self.sham_memory_id,
            self.victim_principal_id,
            self.observer_principal_id,
            self.no_hidden_signal_memory_id,
            self.hidden_signal_memory_id,
            self.allowed_state_diff_path,
        )
        if any(not value for value in identifiers):
            raise ValueError("RISI-C oracle identifiers must not be empty")
        if self.canary_memory_id == self.sham_memory_id:
            raise ValueError("RISI-C canary and sham memories must differ")
        if self.no_hidden_signal_memory_id == self.hidden_signal_memory_id:
            raise ValueError("RISI-C signal memories must differ")
        if self.victim_principal_id == self.observer_principal_id:
            raise ValueError("RISI-C victim and observer principals must differ")
        if not self.allowed_state_diff_path.startswith("/"):
            raise ValueError("RISI-C state-diff path must be a JSON pointer")
        if self.probe_budget != 1:
            raise ValueError("M1 RISI-C probe_budget must be exactly 1")
        for value in (self.positive_minimum_advantage, self.negative_maximum_advantage):
            if not math.isfinite(value) or value < 0.0 or value > 0.5:
                raise ValueError("RISI-C advantage thresholds must be within [0.0, 0.5]")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the evaluator-only oracle representation."""
        return {
            "canary_memory_id": self.canary_memory_id,
            "canary_token": self.canary_token,
            "sham_memory_id": self.sham_memory_id,
            "victim_principal_id": self.victim_principal_id,
            "observer_principal_id": self.observer_principal_id,
            "no_hidden_signal_memory_id": self.no_hidden_signal_memory_id,
            "hidden_signal_memory_id": self.hidden_signal_memory_id,
            "allowed_state_diff_path": self.allowed_state_diff_path,
            "probe_budget": self.probe_budget,
            "positive_minimum_advantage": self.positive_minimum_advantage,
            "negative_maximum_advantage": self.negative_maximum_advantage,
        }


@dataclass(frozen=True, slots=True)
class StateDifference:
    """Record one canonical JSON-pointer difference between paired target states."""

    path: str
    no_hidden_present: bool
    no_hidden_value: JsonValue
    hidden_present: bool
    hidden_value: JsonValue

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable difference record."""
        return {
            "path": self.path,
            "no_hidden_present": self.no_hidden_present,
            "no_hidden_value": self.no_hidden_value,
            "hidden_present": self.hidden_present,
            "hidden_value": self.hidden_value,
        }


@dataclass(frozen=True, slots=True)
class RisiCArmAssessment:
    """Record the frozen classifier result for one paired arm."""

    arm: RisiCArm
    label: int
    prediction: int | None
    correct: bool
    observer_view_sha256: str
    final_state_sha256: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the arm-assessment representation."""
        return {
            "arm": self.arm.value,
            "label": self.label,
            "prediction": self.prediction,
            "correct": self.correct,
            "observer_view_sha256": self.observer_view_sha256,
            "final_state_sha256": self.final_state_sha256,
        }


@dataclass(frozen=True, slots=True)
class RisiCPairAssessment:
    """Record one vulnerable or pure-read paired RISI-C assessment."""

    pair: RisiCPair
    classification: RisiCClassification
    accuracy: float
    advantage: float
    canary_absent: bool
    observer_budget_respected: bool
    sole_mediator: bool
    state_differences: tuple[StateDifference, ...]
    arms: tuple[RisiCArmAssessment, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the pair-assessment representation."""
        return {
            "pair": self.pair.value,
            "classification": self.classification.value,
            "accuracy": self.accuracy,
            "advantage": self.advantage,
            "canary_absent": self.canary_absent,
            "observer_budget_respected": self.observer_budget_respected,
            "sole_mediator": self.sole_mediator,
            "state_differences": [difference.to_json() for difference in self.state_differences],
            "arms": [arm.to_json() for arm in self.arms],
        }


@dataclass(frozen=True, slots=True)
class RisiCComparisonAssessment:
    """Record the complete vulnerable and pure-read DEP-02 comparison."""

    scenario_id: str
    shared_initial_state_sha256: str
    result: RisiCComparisonResult
    pairs: tuple[RisiCPairAssessment, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the comparison-assessment representation."""
        return {
            "schema_version": 1,
            "scenario_id": self.scenario_id,
            "shared_initial_state_sha256": self.shared_initial_state_sha256,
            "result": self.result.value,
            "pairs": [pair.to_json() for pair in self.pairs],
        }


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _state_differences(no_hidden: Any, hidden: Any, path: str = "") -> tuple[StateDifference, ...]:
    if isinstance(no_hidden, dict) and isinstance(hidden, dict):
        differences: list[StateDifference] = []
        for key in sorted(set(no_hidden) | set(hidden)):
            left = no_hidden.get(key, _MISSING)
            right = hidden.get(key, _MISSING)
            child = f"{path}/{_pointer_token(str(key))}"
            if left is _MISSING or right is _MISSING:
                differences.append(
                    StateDifference(
                        path=child,
                        no_hidden_present=left is not _MISSING,
                        no_hidden_value=None if left is _MISSING else normalize_json_value(left),
                        hidden_present=right is not _MISSING,
                        hidden_value=None if right is _MISSING else normalize_json_value(right),
                    )
                )
            else:
                differences.extend(_state_differences(left, right, child))
        return tuple(differences)
    if isinstance(no_hidden, (list, tuple)) and isinstance(hidden, (list, tuple)):
        differences = []
        for index in range(max(len(no_hidden), len(hidden))):
            left = no_hidden[index] if index < len(no_hidden) else _MISSING
            right = hidden[index] if index < len(hidden) else _MISSING
            child = f"{path}/{index}"
            if left is _MISSING or right is _MISSING:
                differences.append(
                    StateDifference(
                        path=child,
                        no_hidden_present=left is not _MISSING,
                        no_hidden_value=None if left is _MISSING else normalize_json_value(left),
                        hidden_present=right is not _MISSING,
                        hidden_value=None if right is _MISSING else normalize_json_value(right),
                    )
                )
            else:
                differences.extend(_state_differences(left, right, child))
        return tuple(differences)
    if normalize_json_value(no_hidden) == normalize_json_value(hidden):
        return ()
    return (
        StateDifference(
            path=path or "/",
            no_hidden_present=True,
            no_hidden_value=normalize_json_value(no_hidden),
            hidden_present=True,
            hidden_value=normalize_json_value(hidden),
        ),
    )


def state_differences(
    no_hidden: StateSnapshot,
    hidden: StateSnapshot,
) -> tuple[StateDifference, ...]:
    """Return the complete deterministic target-state diff for one pair.

    Args:
        no_hidden: Final state for the matched sham arm.
        hidden: Final state for the hidden-retrieval arm.

    Returns:
        Ordered JSON-pointer difference records.
    """
    return _state_differences(no_hidden.to_json(), hidden.to_json())


def _prediction(view: ObserverView, oracle: RisiCOracle) -> int:
    if len(view.exchanges) != oracle.probe_budget:
        raise ValueError("observer view does not match the frozen probe budget")
    response_ids = view.exchanges[0].response_memory_ids
    if response_ids == (oracle.hidden_signal_memory_id,):
        return 1
    if response_ids == (oracle.no_hidden_signal_memory_id,):
        return 0
    raise ValueError("observer response is outside the frozen classifier domain")


def _canary_absent(view: ObserverView, oracle: RisiCOracle) -> bool:
    serialized = canonical_json(view.to_json())
    return oracle.canary_memory_id not in serialized and oracle.canary_token not in serialized


def assess_risi_c_pair(
    pair: RisiCPair,
    no_hidden_state: StateSnapshot,
    hidden_state: StateSnapshot,
    no_hidden_view: ObserverView,
    hidden_view: ObserverView,
    oracle: RisiCOracle,
) -> RisiCPairAssessment:
    """Assess one paired observer experiment using the frozen deterministic classifier.

    Args:
        pair: Vulnerable or pure-read comparison identity.
        no_hidden_state: Final target state for the sham arm.
        hidden_state: Final target state for the hidden arm.
        no_hidden_view: Authorized observer view from the sham arm.
        hidden_view: Authorized observer view from the hidden arm.
        oracle: Evaluator-only assignment, classifier, and threshold contract.

    Returns:
        Conservative paired RISI-C assessment.
    """
    views = (
        (RisiCArm.SHAM, 0, no_hidden_view, no_hidden_state),
        (RisiCArm.HIDDEN, 1, hidden_view, hidden_state),
    )
    arms: list[RisiCArmAssessment] = []
    for arm, label, view, state in views:
        try:
            prediction: int | None = _prediction(view, oracle)
        except ValueError:
            prediction = None
        arms.append(
            RisiCArmAssessment(
                arm=arm,
                label=label,
                prediction=prediction,
                correct=prediction == label,
                observer_view_sha256=canonical_sha256(view.to_json()),
                final_state_sha256=canonical_sha256(state.to_json()),
            )
        )
    accuracy = sum(arm.correct for arm in arms) / len(arms)
    advantage = abs(accuracy - 0.5)
    differences = state_differences(no_hidden_state, hidden_state)
    canary_absent = _canary_absent(no_hidden_view, oracle) and _canary_absent(hidden_view, oracle)
    budget_respected = all(len(view.exchanges) == oracle.probe_budget for _, _, view, _ in views)
    expected_mediator = (
        len(differences) == 1
        and differences[0].path == oracle.allowed_state_diff_path
        and differences[0].no_hidden_present
        and differences[0].hidden_present
        and differences[0].no_hidden_value == 0
        and differences[0].hidden_value == 1
    )
    sole_mediator = expected_mediator if pair is RisiCPair.VULNERABLE else not differences
    if not canary_absent:
        classification = RisiCClassification.DIRECT_DISCLOSURE
    elif not budget_respected or any(arm.prediction is None for arm in arms):
        classification = RisiCClassification.INCONCLUSIVE
    elif pair is RisiCPair.VULNERABLE:
        classification = (
            RisiCClassification.RISI_C
            if advantage >= oracle.positive_minimum_advantage and sole_mediator
            else RisiCClassification.CONFOUNDED
        )
    else:
        classification = (
            RisiCClassification.NO_FAILURE
            if advantage <= oracle.negative_maximum_advantage and sole_mediator
            else RisiCClassification.CONFOUNDED
        )
    return RisiCPairAssessment(
        pair=pair,
        classification=classification,
        accuracy=accuracy,
        advantage=advantage,
        canary_absent=canary_absent,
        observer_budget_respected=budget_respected,
        sole_mediator=sole_mediator,
        state_differences=differences,
        arms=tuple(arms),
    )


def assess_risi_c_comparison(
    scenario_id: str,
    shared_initial_state_sha256: str,
    vulnerable: RisiCPairAssessment,
    pure_read: RisiCPairAssessment,
) -> RisiCComparisonAssessment:
    """Assess complete controlled RISI-C recovery and its pure-read ablation.

    Args:
        scenario_id: Synthetic scenario identifier.
        shared_initial_state_sha256: Digest binding all four arms to one snapshot.
        vulnerable: Vulnerable shared-counter pair assessment.
        pure_read: Pure-read negative pair assessment.

    Returns:
        Complete comparison assessment.
    """
    if vulnerable.pair is not RisiCPair.VULNERABLE:
        raise ValueError("vulnerable assessment has the wrong pair identity")
    if pure_read.pair is not RisiCPair.PURE_READ:
        raise ValueError("pure-read assessment has the wrong pair identity")
    recovered = (
        vulnerable.classification is RisiCClassification.RISI_C
        and pure_read.classification is RisiCClassification.NO_FAILURE
        and vulnerable.sole_mediator
        and pure_read.sole_mediator
        and vulnerable.canary_absent
        and pure_read.canary_absent
    )
    return RisiCComparisonAssessment(
        scenario_id=scenario_id,
        shared_initial_state_sha256=shared_initial_state_sha256,
        result=RisiCComparisonResult.CONTROLLED_MECHANISM_RECOVERED
        if recovered
        else RisiCComparisonResult.COMPARISON_FAILED,
        pairs=(vulnerable, pure_read),
    )
