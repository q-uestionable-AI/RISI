from pathlib import Path

import pytest

from risi.artifacts import ArtifactError, create_evidence_bundle, json_bytes, json_lines_bytes
from risi.evidence import compare_campaign_bundles, inspect_campaign_bundle
from risi.replay import replay_campaign_bundle


def _bundle(root: Path, campaign_id: str = "sacrificial-trace") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "target_manifest_sha256": "a" * 64,
        "input_inventory_sha256": "b" * 64,
        "world_count": 1,
        "observations_per_world": 2,
        "total_observations": 2,
        "top_k": 5,
        "retrieval_mode": "semantic-vector",
        "evidence_relative_path": "sacrificial",
        "expires_on": "2026-08-19",
        "validation_only": False,
        "metadata": {},
    }
    observation = {
        "schema_version": 1,
        "world_id": "world-001",
        "condition": "baseline",
        "budget": 0,
        "target": {"hits": []},
        "non_target": {"hits": []},
    }
    evaluation = {
        "schema_version": 1,
        "world_id": "world-001",
        "condition": "baseline",
        "budget": 0,
        "target": {"critical_recalled": False, "critical_rank": None},
        "non_target": {"critical_recalled": False, "critical_rank": None},
    }
    result = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "status": "completed",
        "world_count": 1,
        "observation_count": 2,
        "request_count": 1,
    }
    create_evidence_bundle(
        root,
        campaign_id,
        {
            "campaign-manifest.json": json_bytes(manifest),
            "target-manifest-digest.json": json_bytes({"target_manifest_sha256": "a" * 64}),
            "observations.jsonl": json_lines_bytes((observation,)),
            "evaluator-assessments.jsonl": json_lines_bytes((evaluation,)),
            "result.json": json_bytes(result),
        },
        max_bytes=1_000_000,
    )
    return root / campaign_id


def test_campaign_bundle_is_inspectable_comparable_and_replayable(tmp_path: Path) -> None:
    first = _bundle(tmp_path / "first")
    second = _bundle(tmp_path / "second")

    summary = inspect_campaign_bundle(first)
    comparison = compare_campaign_bundles(first, second)
    replay = replay_campaign_bundle(first)

    assert summary["observation_count"] == 2
    assert comparison["equal"] is True
    assert replay["equal"] is True
    assert replay["observation_count"] == 2


def test_campaign_replay_detects_tampering(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    (bundle / "observations.jsonl").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ArtifactError):
        replay_campaign_bundle(bundle)
