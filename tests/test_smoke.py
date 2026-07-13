import json
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from risi import __version__
from risi.cli import app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_package_version_matches_project_metadata() -> None:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)

    assert project["project"]["version"] == __version__


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_smoke_command() -> None:
    result = runner.invoke(app, ["smoke"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "risi smoke: ok"


def test_json_schemas_are_parseable() -> None:
    schema_paths = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))

    assert schema_paths
    for schema_path in schema_paths:
        with schema_path.open(encoding="utf-8") as schema_file:
            schema = json.load(schema_file)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
