from dataclasses import replace
from pathlib import Path

import pytest

from risi.artifacts import ArtifactError
from risi.evidence import compare_bundles, inspect_bundle, recover_existing_result
from risi.operator.models import load_approval_record, load_run_manifest
from risi.runner import RunExecution, run_guarded

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-01-local-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-01-local-reference.approval.json"
OTHER_MANIFEST = EXAMPLES / "dat-01-local-reference.manifest.json"
OTHER_APPROVAL = EXAMPLES / "dat-01-local-reference.approval.json"


def _execute(
    root: Path,
    manifest_path: Path = MANIFEST,
    approval_path: Path = APPROVAL,
) -> RunExecution:
    return run_guarded(
        load_run_manifest(manifest_path),
        load_approval_record(approval_path),
        SCENARIO_ROOT,
        root,
    )


def test_inspect_returns_only_verified_closed_summary(tmp_path: Path) -> None:
    execution = _execute(tmp_path)

    summary = inspect_bundle(execution.bundle_path)
    resource_use = summary.resource_use.to_json()

    assert set(summary.to_json()) == {
        "run_id",
        "manifest_sha256",
        "scenario",
        "policy",
        "result",
        "resource_use",
        "inventory_sha256",
        "bundle_hash",
        "inventoried_paths",
    }
    assert summary.run_id == "dep-01-local-reference"
    assert summary.scenario == "DEP-01"
    assert summary.policy == "pure-read"
    assert summary.result.value == "safe"
    assert resource_use["episodes"]["consumed"] == 1
    assert resource_use["retrieval_calls"]["consumed"] == 1
    assert resource_use["logical_steps"]["consumed"] == 3
    assert resource_use["artifact_bytes"]["consumed"] == execution.verification.total_bytes
    assert "execution.json" in summary.inventoried_paths
    assert "inventory.json" not in summary.inventoried_paths


def test_compare_reports_exact_equality_for_separate_deterministic_roots(
    tmp_path: Path,
) -> None:
    first = _execute(tmp_path / "manual")
    second = _execute(tmp_path / "agent")

    comparison = compare_bundles(first.bundle_path, second.bundle_path)

    assert comparison.equal
    assert comparison.differences == ()
    assert comparison.bundle_a.inventory_sha256 == comparison.bundle_b.inventory_sha256
    assert comparison.bundle_a.bundle_hash == comparison.bundle_b.bundle_hash


def test_compare_reports_stable_paths_and_semantic_anchors(tmp_path: Path) -> None:
    first = _execute(tmp_path / "first")
    second = _execute(tmp_path / "second", OTHER_MANIFEST, OTHER_APPROVAL)

    comparison = compare_bundles(first.bundle_path, second.bundle_path)
    differences = [item.to_json() for item in comparison.differences]

    assert not comparison.equal
    assert differences == sorted(
        differences,
        key=lambda item: (
            0 if item["scope"] == "evidence_path" else 1,
            item["path"],
        ),
    )
    assert {item["path"] for item in differences if item["scope"] == "semantic_anchor"} >= {
        "/run_id",
        "/manifest_sha256",
        "/scenario",
        "/inventory_sha256",
        "/bundle_hash",
    }
    assert any(
        item["scope"] == "evidence_path" and item["path"] == "manifest.json" for item in differences
    )


def test_completed_run_reinvocation_reuses_verified_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_run_manifest(MANIFEST)
    approval = load_approval_record(APPROVAL)
    first = run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)

    monkeypatch.setattr(
        "risi.runner._execute_pure_read",
        lambda *args, **kwargs: pytest.fail("completed run was re-executed"),
    )
    second = run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)

    assert first.result.data["reused"] is False
    assert second.result.data["reused"] is True
    assert second.verification == first.verification
    assert second.bundle_path == first.bundle_path


def test_recovery_rejects_tamper_without_overwrite_or_delete(tmp_path: Path) -> None:
    execution = _execute(tmp_path)
    decision = execution.bundle_path / "decision.json"
    decision.write_text('{"action":"changed"}\n', encoding="utf-8")

    with pytest.raises(ArtifactError, match="integrity"):
        recover_existing_result(tmp_path, load_run_manifest(MANIFEST))

    assert decision.read_text(encoding="utf-8") == '{"action":"changed"}\n'


def test_inspect_and_compare_reject_tampered_inputs(tmp_path: Path) -> None:
    first = _execute(tmp_path / "first")
    second = _execute(tmp_path / "second")
    (second.bundle_path / "decision.json").write_text('{"action":"changed"}\n', encoding="utf-8")

    with pytest.raises(ArtifactError, match="integrity"):
        inspect_bundle(second.bundle_path)
    with pytest.raises(ArtifactError, match="integrity"):
        compare_bundles(first.bundle_path, second.bundle_path)


def test_recovery_rejects_different_manifest_material(tmp_path: Path) -> None:
    execution = _execute(tmp_path)
    manifest = replace(load_run_manifest(MANIFEST), seed=18)

    with pytest.raises(ArtifactError, match="does not match"):
        recover_existing_result(tmp_path, manifest)

    assert execution.bundle_path.is_dir()


def test_recovery_rejects_incomplete_final_path_and_ignores_staging(tmp_path: Path) -> None:
    manifest = load_run_manifest(MANIFEST)
    staging = tmp_path / ".risi-staging-interrupted"
    staging.mkdir()
    assert recover_existing_result(tmp_path, manifest) is None

    final = tmp_path / manifest.run_id
    final.mkdir()
    (final / "execution.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ArtifactError, match="inventory"):
        recover_existing_result(tmp_path, manifest)

    assert staging.is_dir()
    assert final.is_dir()
