from __future__ import annotations

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
    assert "Repository checks passed" in result.stdout


def test_reset_requires_confirmation() -> None:
    result = runner.invoke(app, ["lab", "reset"])
    assert result.exit_code == 1
    assert "--yes" in result.stdout


def test_lab_help() -> None:
    result = runner.invoke(app, ["lab", "--help"])
    assert result.exit_code == 0
    assert "Local lab lifecycle" in result.stdout
