import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from risi.artifacts import ArtifactError, verify_evidence_bundle
from risi.budget import BudgetExhaustedError
from risi.cli import app
from risi.operator.models import load_approval_record, load_run_manifest
from risi.replay import read_verified_report, replay_bundle
from risi.runner import run_guarded, validate_run
from risi.scenarios import RegionDecisionProtocol, load_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-01-local-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-01-local-reference.approval.json"
OBLIGATION_MANIFEST = EXAMPLES / "dat-01-local-reference.manifest.json"
OBLIGATION_APPROVAL = EXAMPLES / "dat-01-local-reference.approval.json"
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

    for command in ("verify", "inspect", "replay"):
        result = runner.invoke(app, [command, str(bundle), "--format", "json"])
        assert result.exit_code == 0, result.stdout
        assert json.loads(result.stdout)["status"] == "ok"

    comparison = runner.invoke(
        app,
        ["compare", str(bundle), str(bundle), "--format", "json"],
    )
    assert comparison.exit_code == 0, comparison.stdout
    assert json.loads(comparison.stdout)["data"]["equal"] is True


def test_cli_reinvocation_returns_reused_verified_result(tmp_path: Path) -> None:
    arguments = [
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
    ]

    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)

    assert first.exit_code == second.exit_code == 0
    first_payload = json.loads(first.stdout)
    second_payload = json.loads(second.stdout)
    assert first_payload["data"]["reused"] is False
    assert second_payload["data"]["reused"] is True
    assert first_payload["data"]["bundle_hash"] == second_payload["data"]["bundle_hash"]


def test_budget_exhaustion_has_distinct_machine_result_and_no_bundle(tmp_path: Path) -> None:
    manifest = replace(
        load_run_manifest(MANIFEST),
        limits=replace(load_run_manifest(MANIFEST).limits, logical_steps=2),
    )
    approval = replace(
        load_approval_record(APPROVAL),
        manifest_sha256=manifest.digest,
    )
    manifest_path = tmp_path / "manifest.json"
    approval_path = tmp_path / "approval.json"
    manifest_path.write_text(json.dumps(manifest.to_json()), encoding="utf-8")
    approval_path.write_text(json.dumps(approval.to_json()), encoding="utf-8")
    artifact_root = tmp_path / "artifacts"

    result = runner.invoke(
        app,
        [
            "run",
            str(manifest_path),
            "--approval",
            str(approval_path),
            "--scenario-root",
            str(SCENARIO_ROOT),
            "--artifact-root",
            str(artifact_root),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 6, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "resource_exhausted"
    assert payload["errors"][0]["code"] == "budget_exhausted"
    assert payload["data"]["exhaustion"]["resource"] == "logical_steps"
    assert not (artifact_root / manifest.run_id).exists()


def test_service_budget_exhaustion_is_not_an_experimental_result(tmp_path: Path) -> None:
    manifest = replace(
        load_run_manifest(MANIFEST),
        limits=replace(load_run_manifest(MANIFEST).limits, logical_steps=2),
    )
    approval = replace(load_approval_record(APPROVAL), manifest_sha256=manifest.digest)

    with pytest.raises(BudgetExhaustedError):
        run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)

    assert not (tmp_path / manifest.run_id).exists()


def test_artifact_budget_covers_inventory_and_prevents_finalization(tmp_path: Path) -> None:
    manifest = replace(
        load_run_manifest(MANIFEST),
        limits=replace(load_run_manifest(MANIFEST).limits, artifact_bytes=1),
    )
    approval = replace(load_approval_record(APPROVAL), manifest_sha256=manifest.digest)

    with pytest.raises(BudgetExhaustedError) as raised:
        run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)

    assert raised.value.resource.value == "artifact_bytes"
    assert not (tmp_path / manifest.run_id).exists()


def test_cooperative_interruption_has_distinct_exit_and_no_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt(*args, **kwargs) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("risi.cli.run_guarded", interrupt)

    result = runner.invoke(
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

    assert result.exit_code == 130, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "interrupted"
    assert payload["errors"][0]["code"] == "interrupted"
    assert not (tmp_path / "dep-01-local-reference").exists()


def test_interrupt_after_atomic_finalization_recovers_completed_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def complete_then_interrupt(*args, **kwargs) -> None:
        run_guarded(*args, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr("risi.cli.run_guarded", complete_then_interrupt)
    result = runner.invoke(
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

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["data"]["reused"] is True
    assert (tmp_path / "dep-01-local-reference" / "inventory.json").is_file()


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


def test_validate_rejects_region_protocol_before_pure_read_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = load_scenario(
        SCENARIO_ROOT / "examples" / "dep-01-pure-read.json",
        run_id="dep-01-local-reference",
        seed=17,
        max_input_bytes=100_000,
        max_memory_records=100,
    )
    region_protocol = RegionDecisionProtocol(
        principal_id=scenario.protocol.principal_id,
        tenant_id=scenario.protocol.tenant_id,
        query=scenario.protocol.query,
        top_k=scenario.protocol.top_k,
        dataset_class_fact="dataset_class",
        requested_region_fact="requested_region",
        restricted_dataset_class="D-amber",
        prohibited_region="R3",
        required_memory_id=scenario.protocol.required_memory_id,
        action_if_prohibited="REJECT_REGION",
        action_if_allowed="PROPOSE_REGION",
        allowed_alternatives=("R1", "R2"),
    )
    monkeypatch.setattr(
        "risi.runner.load_scenario",
        lambda *args, **kwargs: replace(scenario, protocol=region_protocol),
    )

    with pytest.raises(TypeError, match="approval or obligation decision protocol"):
        validate_run(
            load_run_manifest(MANIFEST),
            load_approval_record(APPROVAL),
            SCENARIO_ROOT,
        )


@pytest.mark.parametrize(
    ("manifest_path", "approval_path", "wrong_provider"),
    (
        (MANIFEST, APPROVAL, "deterministic-obligation"),
        (OBLIGATION_MANIFEST, OBLIGATION_APPROVAL, "deterministic-approval"),
    ),
)
def test_pure_read_protocol_is_bound_to_its_registered_provider(
    manifest_path: Path,
    approval_path: Path,
    wrong_provider: str,
) -> None:
    manifest = replace(load_run_manifest(manifest_path), decision_provider=wrong_provider)
    approval = replace(
        load_approval_record(approval_path),
        manifest_sha256=manifest.digest,
    )

    with pytest.raises(ValueError, match="does not match the scenario protocol"):
        validate_run(manifest, approval, SCENARIO_ROOT)
