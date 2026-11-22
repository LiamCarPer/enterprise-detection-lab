from __future__ import annotations

import json

from edl.models import ArtifactResult, Issue, ValidationReport
from edl.report import render_json, render_markdown, render_table


def _report() -> ValidationReport:
    artifact = ArtifactResult(
        artifact_type="detection",
        artifact_id="DET-IDN-001",
        path="detections/identity/oauth",
        status="tested",
    )
    artifact.issues.append(
        Issue(
            code="fixture.count",
            message="Fixture count mismatch",
            severity="error",
            artifact_type="detection",
            artifact_id="DET-IDN-001",
            path="detections/identity/oauth",
        )
    )
    report = ValidationReport(artifacts=[artifact])
    report.recompute_summary()
    return report


def test_json_report_is_parseable() -> None:
    payload = json.loads(render_json(_report()))
    assert payload["ok"] is False
    assert payload["summary"]["errors"] == 1
    assert payload["artifacts"][0]["id"] == "DET-IDN-001"


def test_markdown_report_contains_artifact() -> None:
    markdown = render_markdown(_report())
    assert "# Validation Report" in markdown
    assert "DET-IDN-001" in markdown
    assert "fixture.count" in markdown


def test_table_has_caption() -> None:
    table = render_table(_report())
    assert table.caption is not None
    assert "1 error" in table.caption


def test_empty_report_is_ok() -> None:
    report = ValidationReport()
    report.recompute_summary()
    assert report.ok
    assert report.to_dict()["summary"]["errors"] == 0
