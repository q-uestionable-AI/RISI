import json
import re
from dataclasses import fields
from pathlib import Path

from risi.canonical import canonical_sha256
from risi.confidentiality import (
    ObserverExchange,
    ObserverView,
    RisiCArm,
    RisiCClassification,
    RisiCComparisonResult,
    RisiCPair,
)
from risi.craf import CrafArm, CrafClassification, CrafComparisonResult, InfluenceLossStage
from risi.models import (
    EpisodeIdentity,
    EventType,
    EventVisibility,
    MemoryRecord,
    MemoryState,
    PolicyConfiguration,
    PolicyIdentity,
    ProposedDecision,
    StateSnapshot,
    TraceEventDraft,
)
from risi.operator.models import ApprovalRecord, CommandResult, ExecutionLimits, RunManifest
from risi.trace import create_event, event_to_json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PROJECT_ROOT / "schemas"
FIXTURE_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "schemas"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def test_every_schema_and_fixture_is_parseable_json() -> None:
    paths = sorted(SCHEMA_ROOT.glob("*.schema.json"))
    paths.extend(sorted(FIXTURE_ROOT.rglob("*.json")))

    assert paths
    for path in paths:
        assert isinstance(_load_json(path), dict)


def test_experiment_boundary_schemas_are_closed() -> None:
    for schema_path in SCHEMA_ROOT.glob("*.schema.json"):
        schema = _load_json(schema_path)
        assert schema["additionalProperties"] is False

    decision_schema = _load_json(SCHEMA_ROOT / "decision.schema.json")
    decision_fields = {field.name for field in fields(ProposedDecision)}
    assert set(decision_schema["required"]) == decision_fields
    assert set(decision_schema["properties"]) == decision_fields


def test_event_schema_vocabulary_matches_python_enum() -> None:
    schema = _load_json(SCHEMA_ROOT / "event.schema.json")
    schema_types = set(schema["properties"]["event_type"]["enum"])

    assert schema_types == {event_type.value for event_type in EventType}


def test_craf_assessment_schema_vocabulary_matches_python_enums() -> None:
    schema = _load_json(SCHEMA_ROOT / "craf-assessment.schema.json")
    arm = schema["$defs"]["armAssessment"]["properties"]

    assert set(arm["arm"]["enum"]) == {item.value for item in CrafArm}
    assert set(arm["classification"]["enum"]) == {item.value for item in CrafClassification}
    assert set(arm["loss_stage"]["enum"]) == {item.value for item in InfluenceLossStage}
    assert set(schema["properties"]["result"]["enum"]) == {
        item.value for item in CrafComparisonResult
    }


def test_risi_c_schemas_match_python_contracts_and_enums() -> None:
    assessment = _load_json(SCHEMA_ROOT / "risi-c-assessment.schema.json")
    pair = assessment["$defs"]["pair"]["properties"]
    arm = assessment["$defs"]["arm"]["properties"]

    assert set(pair["pair"]["enum"]) == {item.value for item in RisiCPair}
    assert set(pair["classification"]["enum"]) == {item.value for item in RisiCClassification}
    assert set(arm["arm"]["enum"]) == {item.value for item in RisiCArm}
    assert set(assessment["properties"]["result"]["enum"]) == {
        item.value for item in RisiCComparisonResult
    }

    observer = _load_json(SCHEMA_ROOT / "observer-view.schema.json")
    assert set(observer["required"]) == {field.name for field in fields(ObserverView)}
    assert set(observer["$defs"]["exchange"]["required"]) == {
        field.name for field in fields(ObserverExchange)
    }


def test_operator_schema_fields_match_python_contracts() -> None:
    contracts = {
        "run-manifest.schema.json": RunManifest,
        "approval.schema.json": ApprovalRecord,
        "result.schema.json": CommandResult,
    }
    for schema_name, contract in contracts.items():
        schema = _load_json(SCHEMA_ROOT / schema_name)
        assert set(schema["required"]) == {field.name for field in fields(contract)}

    limits_schema = _load_json(SCHEMA_ROOT / "run-manifest.schema.json")["properties"]["limits"]
    assert set(limits_schema["required"]) == {field.name for field in fields(ExecutionLimits)}


def test_valid_event_fixture_matches_canonical_python_contract() -> None:
    fixture = _load_json(FIXTURE_ROOT / "valid" / "event.json")
    draft = TraceEventDraft(
        event_id=fixture["event_id"],
        episode_id=fixture["episode_id"],
        sequence=fixture["sequence"],
        logical_time=fixture["logical_time"],
        event_type=EventType(fixture["event_type"]),
        actor_principal_id=fixture["actor_principal_id"],
        visibility=EventVisibility(fixture["visibility"]),
        state_hash_before=fixture["state_hash_before"],
        state_hash_after=fixture["state_hash_after"],
        payload=fixture["payload"],
    )
    event = create_event(draft, fixture["previous_event_hash"])

    assert event_to_json(event) == fixture


def test_state_fixture_has_cross_platform_canonical_digest() -> None:
    state = _load_json(FIXTURE_ROOT / "valid" / "state.json")

    assert (
        canonical_sha256(state)
        == "77ed4b38b03e0a716e52481e30a103fa663d0da81edaa3ea352a993d8d3ea8b2"
    )


def test_valid_state_fixture_matches_canonical_python_contract() -> None:
    fixture = _load_json(FIXTURE_ROOT / "valid" / "state.json")
    episode_data = fixture["episode"]
    policy_data = fixture["policy"]
    memories = tuple(
        MemoryRecord(
            memory_id=memory["memory_id"],
            scenario_id=memory["scenario_id"],
            tenant_id=memory["tenant_id"],
            owner_id=memory["owner_id"],
            source_id=memory["source_id"],
            content=memory["content"],
            access_policy=tuple(memory["access_policy"]),
            logical_created_at=memory["logical_created_at"],
            logical_valid_from=memory["logical_valid_from"],
            logical_valid_until=memory["logical_valid_until"],
            system_criticality=memory["system_criticality"],
            state=MemoryState(memory["state"]),
            metadata=memory["metadata"],
        )
        for memory in fixture["source_memories"]
    )
    snapshot = StateSnapshot(
        snapshot_version=fixture["snapshot_version"],
        episode=EpisodeIdentity(
            scenario_id=episode_data["scenario_id"],
            episode_id=episode_data["episode_id"],
            seed=episode_data["seed"],
        ),
        logical_time=fixture["logical_time"],
        next_event_sequence=fixture["next_event_sequence"],
        source_memories=memories,
        derived_state=fixture["derived_state"],
        indexes=fixture["indexes"],
        queues=fixture["queues"],
        policy=PolicyConfiguration(
            PolicyIdentity(policy_data["name"], policy_data["version"]),
            policy_data["settings"],
        ),
        policy_state=fixture["policy_state"],
    )

    assert snapshot.to_json() == fixture


def test_valid_decision_fixture_matches_canonical_python_contract() -> None:
    fixture = _load_json(FIXTURE_ROOT / "valid" / "decision.json")
    decision = ProposedDecision(
        decision_id=fixture["decision_id"],
        episode_id=fixture["episode_id"],
        action=fixture["action"],
        rationale_memory_ids=tuple(fixture["rationale_memory_ids"]),
        parameters=fixture["parameters"],
    )

    assert decision.to_json() == fixture


def test_invalid_fixtures_exercise_declared_schema_guards() -> None:
    decision_schema = _load_json(SCHEMA_ROOT / "decision.schema.json")
    decision = _load_json(FIXTURE_ROOT / "invalid" / "decision-evaluator-leak.json")
    assert set(decision) - set(decision_schema["properties"]) == {"decision_oracle"}

    state = _load_json(FIXTURE_ROOT / "invalid" / "state-negative-time.json")
    assert state["logical_time"] < 0

    event_schema = _load_json(SCHEMA_ROOT / "event.schema.json")
    event = _load_json(FIXTURE_ROOT / "invalid" / "event-bad-hash.json")
    hash_pattern = event_schema["$defs"]["hash"]["pattern"]
    assert re.fullmatch(hash_pattern, event["state_hash_before"]) is None

    scenario = _load_json(FIXTURE_ROOT / "invalid" / "scenario-missing-oracle.json")
    assert "decision_oracle" not in scenario["evaluator_only"]

    manifest = _load_json(FIXTURE_ROOT / "invalid" / "run-manifest-network.json")
    capability_enum = _load_json(SCHEMA_ROOT / "run-manifest.schema.json")["properties"][
        "capabilities"
    ]["items"]["enum"]
    assert set(manifest["capabilities"]) - set(capability_enum) == {"network.connect"}

    observer_schema = _load_json(SCHEMA_ROOT / "observer-view.schema.json")
    observer = _load_json(FIXTURE_ROOT / "invalid" / "observer-view-evaluator-leak.json")
    assert set(observer) - set(observer_schema["properties"]) == {"hidden_assignment"}


def test_valid_dep_01_fixture_preserves_evaluator_boundary() -> None:
    scenario = _load_json(FIXTURE_ROOT / "valid" / "scenario.json")
    target_memory_fields = set().union(*(memory.keys() for memory in scenario["initial_memories"]))

    assert scenario["scenario_id"] == "DEP-01"
    assert scenario["craf"]["critical_memory_id"] == "DEP-PROD-07"
    assert not {"oracle_truth", "oracle_criticality", "applicability"} & target_memory_fields
    assert "decision_oracle" in scenario["evaluator_only"]
