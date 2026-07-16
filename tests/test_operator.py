from dataclasses import replace
from pathlib import Path

import pytest

from risi.operator.models import ApprovalRecord, Capability, ExecutionLimits, RunManifest
from risi.operator.safety import (
    LOCAL_REFERENCE_POLICY,
    PathBoundaryError,
    authorize_run,
    resolve_existing_path,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = PROJECT_ROOT / "scenarios" / "examples"


def _manifest() -> RunManifest:
    from risi.operator.models import load_run_manifest

    return load_run_manifest(EXAMPLES / "dep-01-local-reference.manifest.json")


def _approval() -> ApprovalRecord:
    from risi.operator.models import load_approval_record

    return load_approval_record(EXAMPLES / "dep-01-local-reference.approval.json")


def _craf_manifest() -> RunManifest:
    from risi.operator.models import load_run_manifest

    return load_run_manifest(EXAMPLES / "dep-01-craf-reference.manifest.json")


def _craf_approval() -> ApprovalRecord:
    from risi.operator.models import load_approval_record

    return load_approval_record(EXAMPLES / "dep-01-craf-reference.approval.json")


def test_example_approval_is_bound_to_canonical_manifest() -> None:
    manifest = _manifest()
    approval = _approval()

    assert manifest.digest == approval.manifest_sha256
    assert authorize_run(manifest, approval).allowed


def test_craf_example_uses_a_separate_closed_policy_and_exact_limits() -> None:
    manifest = _craf_manifest()
    approval = _craf_approval()

    decision = authorize_run(manifest, approval)

    assert decision.allowed
    assert manifest.policy == "craf-reference"
    assert manifest.limits.episodes == 3
    assert manifest.limits.retrieval_calls == 6

    changed = replace(manifest, policy="unknown-policy")
    changed_approval = replace(approval, manifest_sha256=changed.digest)
    denied = authorize_run(changed, changed_approval)
    assert not denied.allowed
    assert "memory_policy_denied" in denied.reason_codes


def test_manifest_cannot_self_grant_or_exceed_profile_limits() -> None:
    manifest = _manifest()
    approval = _approval()
    excessive = replace(
        manifest,
        limits=ExecutionLimits(
            episodes=2,
            retrieval_calls=manifest.limits.retrieval_calls,
            logical_steps=manifest.limits.logical_steps,
            input_bytes=manifest.limits.input_bytes,
            memory_records=manifest.limits.memory_records,
            artifact_bytes=manifest.limits.artifact_bytes,
        ),
    )
    unapproved = replace(
        approval,
        manifest_sha256=excessive.digest,
        capabilities=(Capability.SCENARIO_READ,),
    )

    decision = authorize_run(excessive, unapproved)

    assert not decision.allowed
    assert "limit_exceeded:episodes" in decision.reason_codes
    assert "approval_scope_mismatch" in decision.reason_codes


def test_missing_or_changed_approval_is_denied() -> None:
    manifest = _manifest()
    assert authorize_run(manifest, None).reason_codes == ("approval_missing",)

    changed = replace(_approval(), manifest_sha256="a" * 64)
    assert "approval_manifest_mismatch" in authorize_run(manifest, changed).reason_codes


def test_scenario_paths_are_contained_by_operator_root(tmp_path: Path) -> None:
    root = tmp_path / "scenarios"
    root.mkdir()
    (root / "inside.json").write_text("{}", encoding="utf-8")
    (tmp_path / "outside.json").write_text("{}", encoding="utf-8")

    assert resolve_existing_path(root, "inside.json") == (root / "inside.json").resolve()
    with pytest.raises(PathBoundaryError):
        resolve_existing_path(root, "../outside.json")


def test_profile_has_explicit_non_network_capabilities() -> None:
    profile = LOCAL_REFERENCE_POLICY.to_json()

    assert profile["network"] == "denied"
    assert profile["subprocesses"] == "denied"
    assert profile["credentials"] == "denied"
