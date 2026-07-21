import json
from pathlib import Path

from typer.testing import CliRunner

from risi.adapters.dify import DIFY_API_PATHS
from risi.adapters.external import ExternalTargetManifest
from risi.campaign import (
    CAMPAIGN_CAPABILITIES,
    CampaignApproval,
    CampaignManifest,
    CampaignPurpose,
)
from risi.cli import app
from risi.operator.models import ExecutionProfile

runner = CliRunner()


def _contracts(tmp_path: Path, *, validation_only: bool) -> tuple[Path, Path, Path]:
    target = ExternalTargetManifest(
        1,
        "risi-dify-e1",
        ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE,
        "https://risi-dify-e1",
        "risi-dify-e1",
        "b" * 64,
        "ca.pem",
        "d" * 64,
        "e" * 64,
        DIFY_API_PATHS,
        {"dify_version": "1.15.0"},
    )
    campaign = CampaignManifest(
        1,
        "craf-ret-dify-01",
        target.digest,
        "d" * 64,
        10 if validation_only else 330,
        1 if validation_only else 22,
        10 if validation_only else 7_260,
        5,
        "semantic-vector",
        "Exploration/E1/craf-ret-dify-01",
        "2026-08-19",
        validation_only,
    )
    approval = CampaignApproval(
        1,
        "E2-IMPLEMENT-2026-07-20-01",
        "accepted",
        CampaignPurpose.E2_VALIDATION,
        campaign.digest,
        target.digest,
        campaign.input_inventory_sha256,
        "Richard Spicer",
        tuple(sorted(CAMPAIGN_CAPABILITIES, key=lambda item: item.value)),
        "2026-08-19",
        3,
    )
    paths = (tmp_path / "target.json", tmp_path / "campaign.json", tmp_path / "approval.json")
    for path, value in zip(
        paths, (target.to_json(), campaign.to_json(), approval.to_json()), strict=True
    ):
        path.write_text(json.dumps(value), encoding="utf-8")
    return paths


def test_campaign_prepare_and_status_commands_are_stable_json(tmp_path: Path) -> None:
    target, campaign, approval = _contracts(tmp_path, validation_only=True)
    workspace = tmp_path / "workspace"

    prepared = runner.invoke(
        app,
        [
            "campaign",
            "prepare",
            str(target),
            str(campaign),
            "--approval",
            str(approval),
            "--workspace",
            str(workspace),
            "--format",
            "json",
        ],
    )
    status = runner.invoke(
        app,
        [
            "campaign",
            "status",
            "craf-ret-dify-01",
            "--workspace",
            str(workspace),
            "--format",
            "json",
        ],
    )

    assert prepared.exit_code == 0
    assert json.loads(prepared.stdout)["status"] == "ok"
    assert status.exit_code == 0
    assert json.loads(status.stdout)["data"]["phase"] == "prepared"


def test_full_e1_execute_is_blocked_without_e3_before_secret_or_input_access(
    tmp_path: Path,
) -> None:
    target, campaign, approval = _contracts(tmp_path, validation_only=False)

    result = runner.invoke(
        app,
        [
            "campaign",
            "execute",
            str(target),
            str(campaign),
            "--approval",
            str(approval),
            "--credential",
            str(tmp_path / "missing-secret.json"),
            "--input-root",
            str(tmp_path / "missing-inputs"),
            "--artifact-root",
            str(tmp_path / "forbidden-evidence"),
            "--workspace",
            str(tmp_path / "workspace"),
            "--format",
            "json",
        ],
    )

    payload = json.loads(result.stdout)
    assert result.exit_code == 3
    assert payload["status"] == "blocked"
    assert {item["code"] for item in payload["errors"]} == {"e3_approval_required"}
    assert not (tmp_path / "forbidden-evidence").exists()
