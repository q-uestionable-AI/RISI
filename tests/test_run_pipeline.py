import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from risi.artifacts import ArtifactError, verify_evidence_bundle
from risi.cli import app
from risi.operator.models import load_approval_record, load_run_manifest
from risi.replay import read_verified_report, replay_bundle
from risi.runner import run_guarded

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-01-local-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-01-local-reference.approval.json"
runner = CliRunner()


def _execute(tmp_path: Path) -> Path:
    manifest = load_run_manifest(MANIFEST)
    approval = load_approval_record(APPROVAL)
    execution = run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)
    return execution.bundle_path


def test_dep_01_run_produces_verifiable_replayable_evidence(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)

    verification = verify_evidence_bundle(bundle)
    replay = replay_bundle(bundle)
    report_verification, report = read_verified_report(bundle)

    assert verification.run_id == "dep-01-local-reference"
    assert replay.decision_action == "HOLD_FOR_SECOND_APPROVAL"
    assert replay.safe
    assert replay.event_count == 6
    assert report_verification.inventory_sha256 == verification.inventory_sha256
    assert "No external action was executed" in report
    target = json.loads((bundle / "target-scenario.json").read_text(encoding="utf-8"))
    assert "evaluator_only" not in target
    assert (bundle / "evaluator" / "evaluator-state.json").is_file()


def test_bundle_verification_detects_tampering(tmp_path: Path) -> None:
    bundle = _execute(tmp_path)
    decision_path = bundle / "decision.json"
    decision_path.write_text('{"action":"changed"}\n', encoding="utf-8")

    with pytest.raises(ArtifactError, match="integrity"):
        verify_evidence_bundle(bundle)


def test_cli_exposes_stable_json_run_verify_and_replay(tmp_path: Path) -> None:
    run_result = runner.invoke(
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
            "--format",
            "json",
        ],
    )

    assert run_result.exit_code == 0, run_result.stdout
    run_payload = json.loads(run_result.stdout)
    assert run_payload["status"] == "ok"
    bundle = Path(run_payload["data"]["bundle_path"])

    for command in ("verify", "replay"):
        result = runner.invoke(app, [command, str(bundle), "--format", "json"])
        assert result.exit_code == 0, result.stdout
        assert json.loads(result.stdout)["status"] == "ok"


def test_cli_returns_policy_exit_code_for_unapproved_manifest(tmp_path: Path) -> None:
    approval = json.loads(APPROVAL.read_text(encoding="utf-8"))
    approval["manifest_sha256"] = "a" * 64
    changed_approval = tmp_path / "approval.json"
    changed_approval.write_text(json.dumps(approval), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "validate",
            str(MANIFEST),
            "--approval",
            str(changed_approval),
            "--scenario-root",
            str(SCENARIO_ROOT),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert payload["errors"][0]["code"] == "approval_manifest_mismatch"


def test_cli_returns_input_exit_code_for_unknown_output_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify", str(tmp_path), "--format", "xml"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["errors"][0]["code"] == "invalid_input"
