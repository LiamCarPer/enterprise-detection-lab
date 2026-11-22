from __future__ import annotations

from edl.models import ArtifactResult, Issue, ValidationReport


def _issue(severity: str = "warning") -> Issue:
    return Issue(
        code="test",
        message="test issue",
        severity=severity,  # type: ignore[arg-type]
        artifact_type="detection",
        artifact_id="DET-IDN-001",
        path="detections/identity/oauth",
    )


def test_artifact_result_errors_warnings_and_ok() -> None:
    artifact = ArtifactResult(
        artifact_type="detection",
        artifact_id="DET-IDN-001",
        path="detections/identity/oauth",
        status="tested",
    )
    assert artifact.ok
    artifact.issues.append(_issue("warning"))
    assert artifact.ok
    assert len(artifact.warnings) == 1
    artifact.issues.append(_issue("error"))
    assert not artifact.ok
    assert len(artifact.errors) == 1


def test_report_summary_and_promote_warnings() -> None:
    detection = ArtifactResult("detection", "DET-IDN-001", "detections/identity/oauth", "tested")
    template = ArtifactResult("detection", "DET-END-000", "detections/endpoint/_template", "draft")
    detection.issues.append(_issue("warning"))
    report = ValidationReport(artifacts=[detection, template])
    report.recompute_summary()
    assert report.summary["detections"] == 1
    assert report.summary["templates"] == 1
    assert report.summary["warnings"] == 1
    report.promote_warnings()
    assert report.summary["warnings"] == 0
    assert report.summary["errors"] == 1
    assert not report.ok


def test_to_dict_recomputes_missing_summary() -> None:
    report = ValidationReport()
    payload = report.to_dict()
    assert payload["ok"] is True
    assert payload["summary"]["templates"] == 0


def test_promote_warnings_leaves_errors_unchanged() -> None:
    detection = ArtifactResult("detection", "DET-IDN-001", "detections/identity/oauth", "tested")
    detection.issues.append(_issue("error"))
    report = ValidationReport(artifacts=[detection])
    report.recompute_summary()
    report.promote_warnings()
    assert report.summary["errors"] == 1
    assert report.summary["warnings"] == 0
