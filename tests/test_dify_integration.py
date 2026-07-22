import os
from pathlib import Path
from typing import cast

import pytest

from risi.adapters.dify import DifyKnowledgeAdapter
from risi.adapters.external import load_target_credential
from risi.campaign import authorize_campaign, campaign_preflight, load_campaign_contracts


@pytest.mark.integration
def test_configured_dify_target_passes_authorized_e2_validation() -> None:
    names = (
        "RISI_DIFY_TARGET_MANIFEST",
        "RISI_DIFY_CAMPAIGN_MANIFEST",
        "RISI_DIFY_APPROVAL",
        "RISI_DIFY_CREDENTIAL",
    )
    configured = {name: os.environ.get(name) for name in names}
    if any(value is None for value in configured.values()):
        pytest.skip("set the four explicit RISI Dify E2 integration paths")
    target, campaign, approval = load_campaign_contracts(
        Path(cast(str, configured["RISI_DIFY_TARGET_MANIFEST"])),
        Path(cast(str, configured["RISI_DIFY_CAMPAIGN_MANIFEST"])),
        Path(cast(str, configured["RISI_DIFY_APPROVAL"])),
    )
    decision = authorize_campaign(campaign, target, approval)
    assert decision.allowed
    credential = load_target_credential(Path(cast(str, configured["RISI_DIFY_CREDENTIAL"])), target)
    adapter = DifyKnowledgeAdapter(target, credential)

    result = campaign_preflight(campaign, target, approval, adapter, attempt=1)

    assert result.passed
