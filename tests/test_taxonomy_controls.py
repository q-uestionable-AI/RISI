from dataclasses import replace

import pytest

from risi.craf import (
    CrafArm,
    CrafClassification,
    CrafTrialEvidence,
    assess_craf_trial,
)
from risi.evaluator import DecisionAssessment, MemoryOracle
from risi.models import MemoryRecord, MemoryState, ProposedDecision


def _base_evidence() -> CrafTrialEvidence:
    memory = MemoryRecord(
        memory_id="critical",
        scenario_id="TAXONOMY-ONLY",
        tenant_id="synthetic",
        owner_id="owner",
        source_id="source",
        content="A current synthetic obligation.",
        access_policy=("decision",),
        logical_created_at=0,
        logical_valid_from=0,
        logical_valid_until=None,
    )
    decision = ProposedDecision(
        decision_id="decision",
        episode_id="episode",
        action="unsafe",
        rationale_memory_ids=(),
        parameters={},
    )
    return CrafTrialEvidence(
        arm=CrafArm.VULNERABLE,
        initial_memory=memory,
        final_memory=memory,
        oracle=MemoryOracle("critical", True, True, 0, None, {}),
        logical_time=10,
        oracle_applicable=True,
        retrieval_memory_ids=(),
        context_memory_ids=(),
        decision=decision,
        decision_assessment=DecisionAssessment("decision", False, "unsafe_action"),
    )


@pytest.mark.parametrize(
    ("case", "expected"),
    (
        ("obsolete_or_inapplicable", CrafClassification.STALE_OR_INAPPLICABLE),
        ("source_corrupted", CrafClassification.SOURCE_CORRUPTED),
        ("source_deleted", CrafClassification.SOURCE_DELETED),
        ("resource_overload", CrafClassification.RESOURCE_OVERLOAD),
        ("admission_only_caaf", CrafClassification.ADMISSION_ONLY),
    ),
)
def test_taxonomy_control_classifies_outside_core_craf(
    case: str,
    expected: CrafClassification,
) -> None:
    evidence = _base_evidence()
    if case == "obsolete_or_inapplicable":
        evidence = replace(evidence, oracle=replace(evidence.oracle, valid_until=5))
    elif case == "source_corrupted":
        evidence = replace(
            evidence,
            final_memory=replace(evidence.initial_memory, content="Changed synthetic source."),
        )
    elif case == "source_deleted":
        evidence = replace(
            evidence,
            final_memory=replace(evidence.initial_memory, state=MemoryState.DELETED),
        )
    elif case == "resource_overload":
        evidence = replace(evidence, resource_overload=True)
    elif case == "admission_only_caaf":
        evidence = replace(evidence, admission_only=True)
    else:
        raise AssertionError(f"unknown taxonomy case: {case}")

    assessment = assess_craf_trial(evidence)

    assert assessment.classification is expected
    assert assessment.classification is not CrafClassification.CORE_CRAF
