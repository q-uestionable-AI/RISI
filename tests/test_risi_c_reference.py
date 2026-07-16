import hashlib
import json
from pathlib import Path

import pytest

from risi.artifacts import ArtifactError, json_bytes, verify_evidence_bundle
from risi.canonical import canonical_sha256
from risi.operator.models import load_approval_record, load_run_manifest
from risi.replay import RisiCReplayResult, replay_bundle
from risi.runner import run_guarded

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-02-risi-c-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-02-risi-c-reference.approval.json"


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


def test_four_arm_comparison_recovers_risi_c_with_pure_read_ablation(
    tmp_path: Path,
) -> None:
    bundle = _execute(tmp_path)

    verification = verify_evidence_bundle(bundle)
    replay = replay_bundle(bundle)
    comparison = _load(bundle / "evaluator" / "risi-c-comparison.json")
    by_pair = {item["pair"]: item for item in comparison["pairs"]}
    execution = _load(bundle / "execution.json")

    assert verification.run_id == "dep-02-risi-c-reference"
    assert isinstance(replay, RisiCReplayResult)
    assert replay.comparison_result == "controlled_mechanism_recovered"
    assert replay.event_count == 46
    assert execution["scenario_id"] == "DEP-02"
    assert [(arm.pair, arm.arm, arm.safe) for arm in replay.arms] == [
        ("vulnerable", "sham", True),
        ("vulnerable", "hidden", True),
        ("pure_read", "sham", True),
        ("pure_read", "hidden", True),
    ]
    assert by_pair["vulnerable"]["classification"] == "risi_c"
    assert by_pair["vulnerable"]["advantage"] == 0.5
    assert by_pair["pure_read"]["classification"] == "no_failure"
    assert by_pair["pure_read"]["advantage"] == 0.0
    assert all(item["sole_mediator"] for item in by_pair.values())


def test_observer_evidence_excludes_canary_assignment_state_traces_and_timing(
    tmp_path: Path,
) -> None:
    bundle = _execute(tmp_path)
    evaluator = _load(bundle / "evaluator" / "evaluator-state.json")
    oracle = evaluator["risi_c_oracle"]

    for pair in ("vulnerable", "pure_read"):
        for arm in ("sham", "hidden"):
            view = _load(bundle / "observer" / "pairs" / pair / "arms" / arm / "view.json")
            serialized = json.dumps(view, sort_keys=True)
            exchange = view["exchanges"][0]

            assert set(view) == {"principal_id", "exchanges"}
            assert set(exchange) == {
                "query_index",
                "query",
                "response_memory_ids",
                "response_contents",
                "metadata",
            }
            assert exchange["metadata"] == {"result_count": 1}
            assert oracle["canary_memory_id"] not in serialized
            assert oracle["canary_token"] not in serialized
            assert not {
                "hidden_assignment",
                "events",
                "state",
                "evaluator",
                "elapsed_ms",
                "wall_clock",
            } & set(exchange["metadata"])


def test_vulnerable_pair_records_only_the_approved_target_state_mediator(
    tmp_path: Path,
) -> None:
    bundle = _execute(tmp_path)
    comparison = _load(bundle / "evaluator" / "risi-c-comparison.json")
    by_pair = {item["pair"]: item for item in comparison["pairs"]}

    vulnerable = by_pair["vulnerable"]
    pure_read = by_pair["pure_read"]
    assert vulnerable["state_differences"] == [
        {
            "path": "/derived_state/shared_access_counter",
            "no_hidden_present": True,
            "no_hidden_value": 0,
            "hidden_present": True,
            "hidden_value": 1,
        }
    ]
    assert pure_read["state_differences"] == []


def test_risi_c_replay_rejects_semantic_observer_tampering(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)
    view_path = bundle / "observer" / "pairs" / "vulnerable" / "arms" / "hidden" / "view.json"
    view = _load(view_path)
    view["exchanges"][0]["response_memory_ids"] = ["DEP-HEALTH-ALPHA"]
    view_path.write_bytes(json_bytes(view))
    _rehash_inventory(bundle)

    with pytest.raises(ArtifactError, match="observer response IDs"):
        replay_bundle(bundle)
