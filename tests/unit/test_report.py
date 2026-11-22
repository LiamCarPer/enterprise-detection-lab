from __future__ import annotations

import json

from edl.models import ArtifactResult, Issue, ValidationReport
from edl.report import render_json, render_markdown, render_table


def _report_with_issue(severity: str) -> ValidationReport:
    artifact = ArtifactResult(
        artifact_type="detection",
        artifact_id="DET-IDN-001",
        path="detections/identity/oauth-consent",
        status="tested",
    )
    artifact.issues.append(
        Issue(
            code="test",
            message="test message",
            severity=severity,  # type: ignore[arg-type]
            artifact_type="detection",
            artifact_id="DET-IDN-001",
            path="detections/identity/oauth-consent",
        )
    )
    report = ValidationReport(artifacts=[artifact])
    report.recompute_summary()
    return report


def test_render_table_handles_empty_report() -> None:
    table = render_table(ValidationReport())
    assert table.row_count == 1
    assert "0 error(s)" in str(table.caption)


def test_render_markdown_includes_warnings_and_errors() -> None:
    warnings = render_markdown(_report_with_issue("warning"))
    assert "## Warnings" in warnings
    assert "test message" in warnings

    errors = render_markdown(_report_with_issue("error"))
    assert "## Errors" in errors
    assert "**OK:** no" in errors


def test_json_report_is_parseable() -> None:
    payload = json.loads(render_json(_report_with_issue("error")))
    assert payload["ok"] is False
    assert payload["summary"]["errors"] == 1
    assert payload["artifacts"][0]["id"] == "DET-IDN-001"


def test_markdown_report_contains_artifact() -> None:
    markdown = render_markdown(_report_with_issue("error"))
    assert "# Validation Report" in markdown
    assert "DET-IDN-001" in markdown
    assert "test" in markdown


def test_table_has_caption() -> None:
    table = render_table(_report_with_issue("error"))
    assert table.caption is not None
    assert "1 error" in table.caption


def test_empty_report_is_ok() -> None:
    report = ValidationReport()
    report.recompute_summary()
    assert report.ok
    assert report.to_dict()["summary"]["errors"] == 0
