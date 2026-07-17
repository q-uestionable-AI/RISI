from pathlib import Path
from typing import Any

import pytest

from risi.cli import app
from risi.operator.models import load_approval_record, load_run_manifest
from risi.operator.safety import AuthorizationDecision
from risi.runner import SafetyBlockedError, capabilities_result, run_guarded

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = PROJECT_ROOT / "scenarios"
EXAMPLES = SCENARIO_ROOT / "examples"
MANIFEST = EXAMPLES / "dep-01-local-reference.manifest.json"
APPROVAL = EXAMPLES / "dep-01-local-reference.approval.json"


def _command_name(command_info: Any) -> str:
    explicit = command_info.name
    if explicit is not None:
        return str(explicit)
    callback = command_info.callback
    return str(callback.__name__).removesuffix("_command")


def test_capability_discovery_is_a_complete_a1_lifecycle_table() -> None:
    data = capabilities_result().data
    lifecycle = {item["operation"]: item["disposition"] for item in data["lifecycle"]}

    assert {
        operation for operation, disposition in lifecycle.items() if disposition == "implemented"
    } == {
        "capabilities",
        "validate",
        "run",
        "verify",
        "replay",
        "inspect",
        "compare",
        "report",
        "idempotent-reinvocation",
        "cooperative-interruption",
        "atomic-finalization",
    }
    assert {
        operation for operation, disposition in lifecycle.items() if disposition == "denied"
    } == {
        "status-service",
        "cancel-command",
        "wall-clock-deadlines",
        "automatic-retries",
        "async-jobs",
        "staging-as-evidence",
    }
    assert data["execution_model"] == "synchronous"
    assert data["automatic_retry_count"] == 0


def test_supported_cli_has_no_authority_or_evidence_edit_commands() -> None:
    command_names = {_command_name(command) for command in app.registered_commands}

    assert command_names == {
        "version",
        "smoke",
        "capabilities",
        "validate",
        "run",
        "verify",
        "inspect",
        "compare",
        "replay",
        "report",
    }
    assert set(capabilities_result().data["authority_denials"]) == {
        "approval.create",
        "approval.edit",
        "evaluator.edit",
        "manifest.create",
        "manifest.edit",
        "evidence.edit",
        "evidence.delete",
        "human-review.accept",
    }


def test_state_changing_service_cannot_bypass_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_run_manifest(MANIFEST)
    approval = load_approval_record(APPROVAL)
    denied = AuthorizationDecision(False, ("test_denial",), ())
    monkeypatch.setattr("risi.runner.authorize_run", lambda *args, **kwargs: denied)
    monkeypatch.setattr(
        "risi.runner.load_scenario",
        lambda *args, **kwargs: pytest.fail("scenario loaded after authorization denial"),
    )

    with pytest.raises(SafetyBlockedError):
        run_guarded(manifest, approval, SCENARIO_ROOT, tmp_path)

    assert not (tmp_path / manifest.run_id).exists()
