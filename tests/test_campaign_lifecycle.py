from datetime import date
from pathlib import Path

import pytest

from risi.adapters.dify import DIFY_API_PATHS
from risi.adapters.external import ExternalKnowledgeAdapter, ExternalTargetManifest
from risi.campaign import (
    CAMPAIGN_CAPABILITIES,
    CampaignApproval,
    CampaignManifest,
    CampaignPurpose,
    authorize_campaign,
    campaign_preflight,
    prepare_campaign,
    request_campaign_cancel,
    retain_preflight_result,
)
from risi.operator.models import ExecutionProfile, OperatorInputError
from risi.transport import CancellationToken


class HealthOnlyAdapter(ExternalKnowledgeAdapter):
    def list_knowledge_bases(self, cancellation: CancellationToken) -> tuple[dict, ...]:
        return ()

    def create_knowledge_base(self, name: str, cancellation: CancellationToken) -> str:
        raise NotImplementedError

    def inspect_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> dict:
        raise NotImplementedError

    def delete_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> None:
        raise NotImplementedError

    def create_document(
        self, dataset_id: str, name: str, content: str, cancellation: CancellationToken
    ) -> tuple[str, str]:
        raise NotImplementedError

    def wait_for_indexing(
        self, dataset_id: str, batch_id: str, cancellation: CancellationToken
    ) -> None:
        raise NotImplementedError

    def inspect_segments(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> tuple[dict, ...]:
        raise NotImplementedError

    def retrieve(self, dataset_id: str, query: str, cancellation: CancellationToken):
        raise NotImplementedError

    def delete_document(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> None:
        raise NotImplementedError

    def read_health(self, cancellation: CancellationToken) -> dict:
        return {"status": "healthy", "services": 8}


def _target() -> ExternalTargetManifest:
    return ExternalTargetManifest(
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


def _manifest(target: ExternalTargetManifest, *, validation_only: bool = True) -> CampaignManifest:
    return CampaignManifest(
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


def _approval(
    target: ExternalTargetManifest,
    manifest: CampaignManifest,
    purpose: CampaignPurpose = CampaignPurpose.E2_VALIDATION,
) -> CampaignApproval:
    return CampaignApproval(
        1,
        "E2-IMPLEMENT-2026-07-20-01" if purpose is CampaignPurpose.E2_VALIDATION else "E3-RUN-1",
        "accepted",
        purpose,
        manifest.digest,
        target.digest,
        manifest.input_inventory_sha256,
        "Richard Spicer",
        tuple(sorted(CAMPAIGN_CAPABILITIES, key=lambda item: item.value)),
        "2026-08-19",
        3 if purpose is CampaignPurpose.E2_VALIDATION else 1,
    )


def test_e2_validation_authority_cannot_authorize_full_e1() -> None:
    target = _target()
    campaign = _manifest(target, validation_only=False)
    approval = _approval(target, campaign)

    decision = authorize_campaign(campaign, target, approval, on_date=date(2026, 7, 20))

    assert not decision.allowed
    assert "e3_approval_required" in decision.reason_codes


def test_prepare_and_cancel_are_atomic_and_non_overwriting(tmp_path: Path) -> None:
    target = _target()
    campaign = _manifest(target)
    approval = _approval(target, campaign)

    checkpoint = prepare_campaign(tmp_path, campaign, target, approval)
    cancel_path = request_campaign_cancel(tmp_path, campaign.campaign_id)

    assert checkpoint.phase.value == "prepared"
    assert cancel_path.read_text(encoding="utf-8") == "cancel-requested\n"
    with pytest.raises(OperatorInputError, match="already exists"):
        prepare_campaign(tmp_path, campaign, target, approval)
    with pytest.raises(OperatorInputError, match="already exists"):
        request_campaign_cancel(tmp_path, campaign.campaign_id)


def test_preflight_is_retained_per_attempt_without_overwrite(tmp_path: Path) -> None:
    target = _target()
    campaign = _manifest(target)
    approval = _approval(target, campaign)

    result = campaign_preflight(
        campaign,
        target,
        approval,
        HealthOnlyAdapter(),
        attempt=1,
        validation_runner=lambda adapter: {"validation_passed": True},
    )
    path = retain_preflight_result(tmp_path, result)

    assert result.passed
    assert path.exists()
    with pytest.raises(OperatorInputError, match="already exists"):
        retain_preflight_result(tmp_path, result)
