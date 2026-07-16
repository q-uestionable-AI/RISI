from pathlib import Path

import pytest

from risi.operator.models import OperatorInputError
from risi.scenarios import load_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCENARIO = PROJECT_ROOT / "scenarios" / "examples" / "dep-01-pure-read.json"


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
