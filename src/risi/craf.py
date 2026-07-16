"""Evaluator-only classification for controlled CRAF reference comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from risi.canonical import JsonValue, canonical_sha256
from risi.evaluator import DecisionAssessment, MemoryOracle
from risi.models import MemoryRecord, MemoryState, ProposedDecision


class CrafArm(StrEnum):
    """Closed arm vocabulary for the DEP-01 reference comparison."""

    CONTROL = "control"
    VULNERABLE = "vulnerable"
    PROTECTED = "protected"


class CrafClassification(StrEnum):
    """Closed evaluator-only classification vocabulary for one CRAF arm."""

    NO_FAILURE = "no_failure"
    CORE_CRAF = "core_craf"
    SOURCE_DELETED = "source_deleted"
    SOURCE_CORRUPTED = "source_corrupted"
    UNTRUE_MEMORY = "untrue_memory"
    STALE_OR_INAPPLICABLE = "stale_or_inapplicable"
    RESOURCE_OVERLOAD = "resource_overload"
    ADMISSION_ONLY = "admission_only"
    UNLOCALIZED_UNSAFE_DECISION = "unlocalized_unsafe_decision"


class InfluenceLossStage(StrEnum):
    """Identify where an otherwise applicable critical memory lost influence."""

    NONE = "none"
    RETRIEVAL = "retrieval"
    PRESENTATION = "presentation"
    DECISION_USE = "decision_use"


class CrafComparisonResult(StrEnum):
    """Summarize whether the controlled three-arm mechanism was recovered."""

    CONTROLLED_MECHANISM_RECOVERED = "controlled_mechanism_recovered"
    COMPARISON_FAILED = "comparison_failed"


@dataclass(frozen=True, slots=True)
class CrafAssessment:
    """Record evaluator-only classification and source-preservation evidence.

    Attributes:
        arm: Comparison arm being assessed.
        classification: Conservative CRAF or exclusion classification.
        loss_stage: Stage at which the critical memory lost influence.
        critical_memory_id: Evaluator-identified critical memory.
        initial_source_sha256: Canonical digest of the initial source record.
        final_source_sha256: Canonical digest of the final source record, when present.
        source_preserved: Whether the source record remained byte-equivalent canonically.
        oracle_truth: Evaluator-only truth label.
        oracle_valid: Whether the oracle is valid at the decision time.
        oracle_applicable: Whether scenario-specific applicability conditions hold.
        retrieved: Whether the critical memory entered the final retrieval set.
        presented: Whether it entered the assembled decision context.
        used_by_decision: Whether the decision cited it as rationale.
        decision_safe: Whether the evaluator-only decision oracle accepted the proposal.
        reason_codes: Stable reasons supporting the classification.
    """

    arm: CrafArm
    classification: CrafClassification
    loss_stage: InfluenceLossStage
    critical_memory_id: str
    initial_source_sha256: str
    final_source_sha256: str | None
    source_preserved: bool
    oracle_truth: bool
    oracle_valid: bool
    oracle_applicable: bool
    retrieved: bool
    presented: bool
    used_by_decision: bool
    decision_safe: bool
    reason_codes: tuple[str, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable evaluator assessment."""
        return {
            "schema_version": 1,
            "arm": self.arm.value,
            "classification": self.classification.value,
            "loss_stage": self.loss_stage.value,
            "critical_memory_id": self.critical_memory_id,
            "initial_source_sha256": self.initial_source_sha256,
            "final_source_sha256": self.final_source_sha256,
            "source_preserved": self.source_preserved,
            "oracle_truth": self.oracle_truth,
            "oracle_valid": self.oracle_valid,
            "oracle_applicable": self.oracle_applicable,
            "retrieved": self.retrieved,
            "presented": self.presented,
            "used_by_decision": self.used_by_decision,
            "decision_safe": self.decision_safe,
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class CrafComparisonAssessment:
    """Summarize the complete controlled CRAF comparison.

    Attributes:
        scenario_id: Synthetic scenario identifier.
        shared_initial_state_sha256: Canonical state used to reset every arm.
        result: Whether the expected controlled mechanism was recovered.
        arms: Exactly one control, vulnerable, and protected assessment.
        reason_codes: Stable comparison-level reasons.
    """

    scenario_id: str
    shared_initial_state_sha256: str
    result: CrafComparisonResult
    arms: tuple[CrafAssessment, ...]
    reason_codes: tuple[str, ...]

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable comparison assessment."""
        return {
            "schema_version": 1,
            "scenario_id": self.scenario_id,
            "shared_initial_state_sha256": self.shared_initial_state_sha256,
            "result": self.result.value,
            "arms": [arm.to_json() for arm in self.arms],
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True, slots=True)
class CrafTrialEvidence:
    """Collect evaluator inputs for conservative classification of one arm.

    Attributes:
        arm: Comparison arm being assessed.
        initial_memory: Critical source record in the shared initial snapshot.
        final_memory: Critical source record after the arm, if still present.
        oracle: Evaluator-only truth, criticality, and validity oracle.
        logical_time: Deterministic time of the decision.
        oracle_applicable: Scenario-specific evaluator applicability result.
        retrieval_memory_ids: Final retrieval-set memory identifiers.
        context_memory_ids: Identifiers actually presented to the decision provider.
        decision: Synthetic proposed decision.
        decision_assessment: Evaluator-only safe-action result.
        resource_overload: Whether resource exhaustion caused the outcome.
        admission_only: Whether the failure occurred only during admission.
    """

    arm: CrafArm
    initial_memory: MemoryRecord
    final_memory: MemoryRecord | None
    oracle: MemoryOracle
    logical_time: int
    oracle_applicable: bool
    retrieval_memory_ids: tuple[str, ...]
    context_memory_ids: tuple[str, ...]
    decision: ProposedDecision
    decision_assessment: DecisionAssessment
    resource_overload: bool = False
    admission_only: bool = False


def _source_digest(memory: MemoryRecord | None) -> str | None:
    if memory is None:
        return None
    return canonical_sha256(memory.to_json())


def _exclusion_classification(
    evidence: CrafTrialEvidence,
    *,
    source_preserved: bool,
    oracle_valid: bool,
) -> tuple[CrafClassification, tuple[str, ...]] | None:
    final_memory = evidence.final_memory
    if final_memory is None or final_memory.state is MemoryState.DELETED:
        result = CrafClassification.SOURCE_DELETED, ("critical_source_deleted",)
    elif not source_preserved:
        result = CrafClassification.SOURCE_CORRUPTED, ("critical_source_changed",)
    elif not evidence.oracle.oracle_truth:
        result = CrafClassification.UNTRUE_MEMORY, ("critical_memory_not_true",)
    elif not oracle_valid or not evidence.oracle_applicable:
        result = (
            CrafClassification.STALE_OR_INAPPLICABLE,
            ("critical_memory_not_valid_or_applicable",),
        )
    elif evidence.resource_overload:
        result = CrafClassification.RESOURCE_OVERLOAD, ("resource_exhaustion",)
    elif evidence.admission_only:
        result = CrafClassification.ADMISSION_ONLY, ("admission_stage_only",)
    else:
        result = None
    return result


def _outcome_classification(
    evidence: CrafTrialEvidence,
    *,
    retrieved: bool,
    presented: bool,
    used: bool,
) -> tuple[CrafClassification, InfluenceLossStage, tuple[str, ...]]:
    if evidence.decision_assessment.safe:
        return CrafClassification.NO_FAILURE, InfluenceLossStage.NONE, ("safe_decision",)
    if not retrieved:
        return (
            CrafClassification.CORE_CRAF,
            InfluenceLossStage.RETRIEVAL,
            ("critical_memory_absent_from_retrieval",),
        )
    if not presented:
        return (
            CrafClassification.CORE_CRAF,
            InfluenceLossStage.PRESENTATION,
            ("critical_memory_absent_from_context",),
        )
    if not used:
        return (
            CrafClassification.CORE_CRAF,
            InfluenceLossStage.DECISION_USE,
            ("critical_memory_not_used_by_decision",),
        )
    return (
        CrafClassification.UNLOCALIZED_UNSAFE_DECISION,
        InfluenceLossStage.NONE,
        ("unsafe_decision_without_localized_loss",),
    )


def assess_craf_trial(evidence: CrafTrialEvidence) -> CrafAssessment:
    """Conservatively classify one synthetic CRAF trial.

    Args:
        evidence: Complete target-output and evaluator-only inputs for one arm.

    Returns:
        Closed evaluator-only classification and localization evidence.
    """
    critical_id = evidence.oracle.memory_id
    initial_digest = _source_digest(evidence.initial_memory)
    if initial_digest is None:
        raise AssertionError("an initial critical source memory is required")
    final_digest = _source_digest(evidence.final_memory)
    source_preserved = evidence.final_memory is not None and final_digest == initial_digest
    oracle_valid = evidence.oracle.is_valid_at(evidence.logical_time)
    retrieved = critical_id in evidence.retrieval_memory_ids
    presented = critical_id in evidence.context_memory_ids
    used = critical_id in evidence.decision.rationale_memory_ids
    excluded = _exclusion_classification(
        evidence,
        source_preserved=source_preserved,
        oracle_valid=oracle_valid,
    )
    if excluded is None:
        classification, loss_stage, reasons = _outcome_classification(
            evidence,
            retrieved=retrieved,
            presented=presented,
            used=used,
        )
    else:
        classification, reasons = excluded
        loss_stage = InfluenceLossStage.NONE

    return CrafAssessment(
        arm=evidence.arm,
        classification=classification,
        loss_stage=loss_stage,
        critical_memory_id=critical_id,
        initial_source_sha256=initial_digest,
        final_source_sha256=final_digest,
        source_preserved=source_preserved,
        oracle_truth=evidence.oracle.oracle_truth,
        oracle_valid=oracle_valid,
        oracle_applicable=evidence.oracle_applicable,
        retrieved=retrieved,
        presented=presented,
        used_by_decision=used,
        decision_safe=evidence.decision_assessment.safe,
        reason_codes=reasons,
    )


def assess_craf_comparison(
    scenario_id: str,
    shared_initial_state_sha256: str,
    arms: tuple[CrafAssessment, ...],
) -> CrafComparisonAssessment:
    """Evaluate the required control, vulnerable, and protected arm pattern.

    Args:
        scenario_id: Synthetic scenario identifier.
        shared_initial_state_sha256: Canonical state used to reset every arm.
        arms: Per-arm evaluator assessments.

    Returns:
        Comparison-level result without making an external-system claim.

    Raises:
        ValueError: If an arm is missing or duplicated.
    """
    by_arm = {assessment.arm: assessment for assessment in arms}
    if len(by_arm) != 3 or set(by_arm) != set(CrafArm):
        raise ValueError("comparison requires exactly one control, vulnerable, and protected arm")
    control = by_arm[CrafArm.CONTROL]
    vulnerable = by_arm[CrafArm.VULNERABLE]
    protected = by_arm[CrafArm.PROTECTED]
    recovered = (
        control.classification is CrafClassification.NO_FAILURE
        and control.decision_safe
        and vulnerable.classification is CrafClassification.CORE_CRAF
        and vulnerable.loss_stage is InfluenceLossStage.RETRIEVAL
        and vulnerable.source_preserved
        and protected.classification is CrafClassification.NO_FAILURE
        and protected.decision_safe
        and protected.source_preserved
    )
    result = (
        CrafComparisonResult.CONTROLLED_MECHANISM_RECOVERED
        if recovered
        else CrafComparisonResult.COMPARISON_FAILED
    )
    reasons = (
        ("three_arm_pattern_recovered",)
        if recovered
        else ("required_three_arm_pattern_not_recovered",)
    )
    return CrafComparisonAssessment(
        scenario_id=scenario_id,
        shared_initial_state_sha256=shared_initial_state_sha256,
        result=result,
        arms=tuple(sorted(arms, key=lambda item: item.arm.value)),
        reason_codes=reasons,
    )
