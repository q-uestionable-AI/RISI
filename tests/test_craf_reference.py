import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from risi.artifacts import ArtifactError, json_bytes, verify_evidence_bundle
from risi.canonical import canonical_sha256
from risi.cli import app
from risi.craf import (
    CrafArm,
    CrafClassification,
    CrafTrialEvidence,
    InfluenceLossStage,
    assess_craf_trial,
)
from risi.evaluator import DecisionAssessment, MemoryOracle
from risi.models import MemoryRecord, ProposedDecision
from risi.operator.models import load_approval_record, load_run_manifest
from risi.replay import CrafReplayResult, replay_bundle
from risi.runner import run_guarded

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-01-craf-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-01-craf-reference.approval.json"


def _execute(tmp_path: Path) -> Path:
    execution = run_guarded(
        load_run_manifest(MANIFEST),
        load_approval_record(APPROVAL),
        SCENARIO_ROOT,
        tmp_path,
    )
    return execution.bundle_path


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _rehash_inventory(bundle: Path) -> None:
    inventory_path = bundle / "inventory.json"
    inventory = _load(inventory_path)
    for entry in inventory["files"]:
        content = (bundle / Path(*entry["path"].split("/"))).read_bytes()
        entry["bytes"] = len(content)
        entry["sha256"] = hashlib.sha256(content).hexdigest()
    inventory["bundle_hash"] = canonical_sha256(inventory["files"])
    inventory_path.write_bytes(json_bytes(inventory))


def test_three_arm_comparison_recovers_controlled_craf_and_protection(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)

    verification = verify_evidence_bundle(bundle)
    replay = replay_bundle(bundle)
    comparison = _load(bundle / "evaluator" / "craf-comparison.json")
    execution = _load(bundle / "execution.json")
    by_arm = {item["arm"]: item for item in comparison["arms"]}

    assert verification.run_id == "dep-01-craf-reference"
    assert isinstance(replay, CrafReplayResult)
    assert replay.comparison_result == "controlled_mechanism_recovered"
    assert replay.event_count == 32
    assert [(arm.arm, arm.safe) for arm in replay.arms] == [
        ("control", True),
        ("vulnerable", False),
        ("protected", True),
    ]
    assert by_arm["control"]["classification"] == "no_failure"
    assert by_arm["vulnerable"]["classification"] == "core_craf"
    assert by_arm["vulnerable"]["loss_stage"] == "retrieval"
    assert by_arm["protected"]["classification"] == "no_failure"
    assert all(item["source_preserved"] for item in by_arm.values())
    assert execution["resource_use"]["episodes"]["consumed"] == 3
    assert execution["resource_use"]["retrieval_calls"]["consumed"] == 6
    assert execution["resource_use"]["logical_steps"]["consumed"] == 12
    assert execution["resource_use"]["artifact_bytes"]["consumed"] == verification.total_bytes


def test_craf_arms_share_initial_state_and_preserve_critical_source(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)
    initial = _load(bundle / "initial-state.json")
    shared_hash = _load(bundle / "evaluator" / "craf-comparison.json")[
        "shared_initial_state_sha256"
    ]

    final_states = {}
    for arm in ("control", "vulnerable", "protected"):
        final = _load(bundle / "arms" / arm / "final-state.json")
        final_states[arm] = final
        assert final["source_memories"] == initial["source_memories"]
        first_event = json.loads(
            (bundle / "arms" / arm / "events.jsonl").read_text(encoding="utf-8").splitlines()[0]
        )
        assert first_event["state_hash_before"] == shared_hash

    assert final_states["vulnerable"]["derived_state"] == final_states["protected"]["derived_state"]
    critical = next(
        item for item in initial["source_memories"] if item["memory_id"] == "DEP-PROD-07"
    )
    assert critical["system_criticality"] == "protected-recall"


def test_craf_evaluator_events_remain_evaluator_only(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)
    target = _load(bundle / "target-scenario.json")
    events = [
        json.loads(line)
        for line in (bundle / "arms" / "vulnerable" / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]

    assert "evaluator_only" not in target
    assert "memory_oracles" not in target
    suppression = [
        event for event in events if event["event_type"] == "critical_memory_suppression"
    ]
    assert len(suppression) == 1
    assert suppression[0]["visibility"] == "evaluator"


def test_craf_replay_rejects_semantic_source_digest_tampering(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)
    assessment_path = bundle / "evaluator" / "arms" / "vulnerable" / "craf-assessment.json"
    comparison_path = bundle / "evaluator" / "craf-comparison.json"
    assessment = _load(assessment_path)
    comparison = _load(comparison_path)
    assessment["initial_source_sha256"] = "a" * 64
    next(item for item in comparison["arms"] if item["arm"] == "vulnerable")[
        "initial_source_sha256"
    ] = "a" * 64
    assessment_path.write_bytes(json_bytes(assessment))
    comparison_path.write_bytes(json_bytes(comparison))
    _rehash_inventory(bundle)

    with pytest.raises(ArtifactError, match="initial source digest"):
        replay_bundle(bundle)


def test_cli_renders_craf_run_and_replay_without_single_decision_fields(tmp_path: Path) -> None:
    cli = CliRunner()
    run_result = cli.invoke(
        app,
        [
            "run",
            str(MANIFEST),
            "--approval",
            str(APPROVAL),
            "--scenario-root",
            str(SCENARIO_ROOT),
            "--artifact-root",
            str(tmp_path),
        ],
    )

    assert run_result.exit_code == 0, run_result.stdout
    assert "controlled_mechanism_recovered" in run_result.stdout
    bundle = tmp_path / "dep-01-craf-reference"
    replay_result = cli.invoke(app, ["replay", str(bundle)])
    assert replay_result.exit_code == 0, replay_result.stdout
    assert "comparison: controlled_mechanism_recovered" in replay_result.stdout


def _trial_evidence() -> CrafTrialEvidence:
    memory = MemoryRecord(
        memory_id="critical",
        scenario_id="DEP-01",
        tenant_id="tenant",
        owner_id="owner",
        source_id="source",
        content="A current critical policy.",
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


def test_craf_classifier_localizes_loss_and_excludes_non_core_failures() -> None:
    evidence = _trial_evidence()

    retrieval_loss = assess_craf_trial(evidence)
    presentation_loss = assess_craf_trial(replace(evidence, retrieval_memory_ids=("critical",)))
    decision_loss = assess_craf_trial(
        replace(
            evidence,
            retrieval_memory_ids=("critical",),
            context_memory_ids=("critical",),
        )
    )
    deleted = assess_craf_trial(replace(evidence, final_memory=None))
    corrupted = assess_craf_trial(
        replace(evidence, final_memory=replace(evidence.initial_memory, content="changed"))
    )
    stale = assess_craf_trial(replace(evidence, oracle=replace(evidence.oracle, valid_until=5)))
    overload = assess_craf_trial(replace(evidence, resource_overload=True))
    admission = assess_craf_trial(replace(evidence, admission_only=True))

    assert retrieval_loss.loss_stage is InfluenceLossStage.RETRIEVAL
    assert presentation_loss.loss_stage is InfluenceLossStage.PRESENTATION
    assert decision_loss.loss_stage is InfluenceLossStage.DECISION_USE
    assert deleted.classification is CrafClassification.SOURCE_DELETED
    assert corrupted.classification is CrafClassification.SOURCE_CORRUPTED
    assert stale.classification is CrafClassification.STALE_OR_INAPPLICABLE
    assert overload.classification is CrafClassification.RESOURCE_OVERLOAD
    assert admission.classification is CrafClassification.ADMISSION_ONLY
    assert all(
        item.classification is not CrafClassification.CORE_CRAF
        for item in (deleted, corrupted, stale, overload, admission)
    )
