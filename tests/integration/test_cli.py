from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from edl.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "edl 0.0.1" in result.stdout


def test_validate_existing_repository() -> None:
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 0
    assert "Validation Report" in result.stdout


def test_validate_json() -> None:
    result = runner.invoke(app, ["validate", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["summary"]["detections"] == 0


def test_report_json() -> None:
    result = runner.invoke(app, ["report", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["errors"] == 0


def test_telemetry_matrix_write_and_check(tmp_path: Path) -> None:
    output = tmp_path / "telemetry-matrix.md"
    write_result = runner.invoke(app, ["telemetry", "matrix", "--output", str(output)])
    assert write_result.exit_code == 0
    assert output.exists()
    assert "Telemetry Matrix" in output.read_text()

    check_result = runner.invoke(
        app,
        ["telemetry", "matrix", "--check", "--output", str(output)],
    )
    assert check_result.exit_code == 0


def test_reset_requires_confirmation() -> None:
    result = runner.invoke(app, ["lab", "reset"])
    assert result.exit_code == 1
    assert "--yes" in result.stdout


def test_lab_help() -> None:
    result = runner.invoke(app, ["lab", "--help"])
    assert result.exit_code == 0
    assert "Local lab lifecycle" in result.stdout
