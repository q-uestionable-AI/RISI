from pathlib import Path

import pytest

from risi.operator.models import OperatorInputError
from risi.scenarios import load_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO = PROJECT_ROOT / "scenarios" / "examples" / "dep-01-pure-read.json"
CRAF_SCENARIO = PROJECT_ROOT / "scenarios" / "examples" / "dep-01-craf.json"
RISI_C_SCENARIO = PROJECT_ROOT / "scenarios" / "examples" / "dep-02-risi-c.json"


def test_dep_01_scenario_loads_with_structural_oracle_separation() -> None:
    scenario = load_scenario(
        SCENARIO,
        run_id="dep-01-test",
        seed=17,
        max_input_bytes=100_000,
        max_memory_records=100,
    )

    assert scenario.scenario_id == "DEP-01"
    assert scenario.protocol.required_memory_id == "DEP-PROD-07"
    assert scenario.evaluator.decision_oracle.safe_actions == ("HOLD_FOR_SECOND_APPROVAL",)
    assert "evaluator_only" not in scenario.target_view()
    assert "memory_oracles" in scenario.evaluator_view()


def test_scenario_enforces_seed_and_input_budgets() -> None:
    with pytest.raises(OperatorInputError, match="seed"):
        load_scenario(
            SCENARIO,
            run_id="dep-01-test",
            seed=99,
            max_input_bytes=100_000,
            max_memory_records=100,
        )


def test_craf_scenario_loads_truthful_authorized_interaction_protocol() -> None:
    scenario = load_scenario(
        CRAF_SCENARIO,
        run_id="dep-01-craf-test",
        seed=17,
        max_input_bytes=100_000,
        max_memory_records=100,
    )

    assert scenario.craf_reference is not None
    assert scenario.craf_reference.principal_id == "dev-aria"
    assert scenario.craf_reference.trigger_memory_id == "DEP-CLOSE-01"
    trigger_oracle = next(
        item
        for item in scenario.evaluator.memory_oracles
        if item.memory_id == scenario.craf_reference.trigger_memory_id
    )
    assert trigger_oracle.oracle_truth
    assert not trigger_oracle.oracle_criticality
    target = scenario.target_view()
    assert target["craf_reference"] == scenario.craf_reference.to_json()
    assert "memory_oracles" not in target
    with pytest.raises(OperatorInputError, match="scenario_sha256"):
        load_scenario(
            SCENARIO,
            run_id="dep-01-test",
            seed=17,
            max_input_bytes=100_000,
            max_memory_records=100,
            expected_sha256="a" * 64,
        )
    with pytest.raises(OperatorInputError, match="input_bytes"):
        load_scenario(
            SCENARIO,
            run_id="dep-01-test",
            seed=17,
            max_input_bytes=10,
            max_memory_records=100,
        )


def test_risi_c_scenario_loads_with_strict_observer_oracle_separation() -> None:
    scenario = load_scenario(
        RISI_C_SCENARIO,
        run_id="dep-02-risi-c-test",
        seed=23,
        max_input_bytes=100_000,
        max_memory_records=100,
    )

    assert scenario.risi_c_reference is not None
    assert scenario.risi_c_oracle is not None
    assert scenario.risi_c_reference.probe_count == 1
    assert scenario.risi_c_reference.observer_principal_id == "ops-niko"
    assert scenario.risi_c_oracle.allowed_state_diff_path == (
        "/derived_state/shared_access_counter"
    )
    target = scenario.target_view()
    evaluator = scenario.evaluator_view()
    assert "risi_c_reference" in target
    assert "risi_c_oracle" not in target
    assert "risi_c_oracle" in evaluator
