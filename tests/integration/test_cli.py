from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from edl.cli import app
from edl.detection import DetectionResult
from edl.errors import DetectionError, IngestError, LabError, ValidationError
from edl.lab import ServiceStatus
from edl.models import ArtifactResult, Issue, ValidationReport

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
    assert payload["summary"]["detections"] == 1


def test_report_json() -> None:
    result = runner.invoke(app, ["report", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["errors"] == 0


def test_new_detection_dry_run() -> None:
    result = runner.invoke(
        app,
        [
            "new",
            "detection",
            "--domain",
            "identity",
            "--slug",
            "test-detection",
            "--id",
            "DET-IDN-999",
            "--title",
            "Test Detection",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Would create" in result.stdout


def test_new_investigation_dry_run() -> None:
    result = runner.invoke(
        app,
        [
            "new",
            "investigation",
            "--slug",
            "test-investigation",
            "--id",
            "INV-999",
            "--title",
            "Test Investigation",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Would create" in result.stdout


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


def _failed_report() -> ValidationReport:
    result = ArtifactResult(
        artifact_type="detection",
        artifact_id="DET-IDN-001",
        path="detections/identity/oauth-consent",
        status="tested",
    )
    result.issues.append(
        Issue(
            code="test",
            message="forced failure",
            severity="error",
            artifact_type="detection",
            artifact_id="DET-IDN-001",
            path="detections/identity/oauth-consent",
        )
    )
    report = ValidationReport(artifacts=[result])
    report.recompute_summary()
    return report


def test_validate_handles_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise ValidationError("cannot read repository")

    monkeypatch.setattr("edl.cli.validate_repository", fail)
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 2
    assert "cannot read repository" in result.stdout


def test_validate_exits_one_for_failed_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.validate_repository", lambda *a, **k: _failed_report())
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 1


def test_validate_json_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.validate_repository", lambda *a, **k: _failed_report())
    result = runner.invoke(app, ["validate", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False


def test_report_rejects_unknown_format() -> None:
    result = runner.invoke(app, ["report", "--format", "xml"])
    assert result.exit_code == 2
    assert "--format must be" in result.stdout


def test_report_handles_runtime_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise ValidationError("cannot read repository")

    monkeypatch.setattr("edl.cli.validate_repository", fail)
    result = runner.invoke(app, ["report"])
    assert result.exit_code == 2
    assert "cannot read repository" in result.stdout


def test_report_markdown_and_table() -> None:
    markdown = runner.invoke(app, ["report", "--format", "markdown"])
    assert markdown.exit_code == 0
    assert markdown.stdout.startswith("# Validation Report")

    table = runner.invoke(app, ["report"])
    assert table.exit_code == 0
    assert "Validation Report" in table.stdout


def test_report_exits_one_for_failed_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.validate_repository", lambda *a, **k: _failed_report())
    result = runner.invoke(app, ["report", "--format", "json"])
    assert result.exit_code == 1


def test_telemetry_matrix_handles_load_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail(_root: Path) -> None:
        raise ValidationError("bad source")

    monkeypatch.setattr("edl.cli.load_sources", fail)
    result = runner.invoke(
        app,
        ["telemetry", "matrix", "--output", str(tmp_path / "matrix.md")],
    )
    assert result.exit_code == 2
    assert "bad source" in result.stdout


def test_telemetry_matrix_detects_stale_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("edl.cli.load_sources", lambda _root: [])
    monkeypatch.setattr("edl.cli.matrix_is_current", lambda _path, _sources: False)
    result = runner.invoke(
        app,
        ["telemetry", "matrix", "--check", "--output", str(tmp_path / "matrix.md")],
    )
    assert result.exit_code == 1
    assert "stale" in result.stdout


def test_new_detection_reports_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(**_kwargs: object) -> None:
        raise ValidationError("invalid detection ID")

    monkeypatch.setattr("edl.cli.create_detection", fail)
    result = runner.invoke(
        app,
        [
            "new",
            "detection",
            "--domain",
            "identity",
            "--slug",
            "oauth-consent",
            "--id",
            "DET-BAD-001",
            "--title",
            "OAuth consent grant",
        ],
    )
    assert result.exit_code == 1
    assert "invalid detection ID" in result.stdout


def test_new_detection_created(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "detections" / "identity" / "oauth-consent"
    monkeypatch.setattr("edl.cli.create_detection", lambda **_kwargs: target)
    result = runner.invoke(
        app,
        [
            "new",
            "detection",
            "--domain",
            "identity",
            "--slug",
            "oauth-consent",
            "--id",
            "DET-IDN-001",
            "--title",
            "OAuth consent grant",
        ],
    )
    assert result.exit_code == 0
    assert "Created" in result.stdout


def test_new_investigation_reports_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(**_kwargs: object) -> None:
        raise ValidationError("invalid investigation ID")

    monkeypatch.setattr("edl.cli.create_investigation", fail)
    result = runner.invoke(
        app,
        [
            "new",
            "investigation",
            "--slug",
            "identity-to-cloud",
            "--id",
            "BAD-001",
            "--title",
            "Identity to cloud",
        ],
    )
    assert result.exit_code == 1
    assert "invalid investigation ID" in result.stdout


def test_new_investigation_created(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "investigations" / "identity-to-cloud"
    monkeypatch.setattr("edl.cli.create_investigation", lambda **_kwargs: target)
    result = runner.invoke(
        app,
        [
            "new",
            "investigation",
            "--slug",
            "identity-to-cloud",
            "--id",
            "INV-001",
            "--title",
            "Identity to cloud",
        ],
    )
    assert result.exit_code == 0
    assert "Created" in result.stdout


def test_lab_up_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.lab_controller.up", lambda: None)
    result = runner.invoke(app, ["lab", "up"])
    assert result.exit_code == 0
    assert "Lab is healthy" in result.stdout

    def fail() -> None:
        raise LabError("compose failed")

    monkeypatch.setattr("edl.cli.lab_controller.up", fail)
    result = runner.invoke(app, ["lab", "up"])
    assert result.exit_code == 2
    assert "compose failed" in result.stdout


def test_lab_down(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("edl.cli.lab_controller.down", lambda: calls.append("down"))
    result = runner.invoke(app, ["lab", "down"])
    assert result.exit_code == 0
    assert calls == ["down"]
    assert "Lab stopped" in result.stdout


def test_lab_status_healthy_and_unhealthy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "edl.cli.lab_controller.status",
        lambda: [ServiceStatus("opensearch", "http://os", True, "green")],
    )
    result = runner.invoke(app, ["lab", "status"])
    assert result.exit_code == 0
    assert "healthy" in result.stdout

    monkeypatch.setattr(
        "edl.cli.lab_controller.status",
        lambda: [ServiceStatus("opensearch", "http://os", False, "red")],
    )
    result = runner.invoke(app, ["lab", "status"])
    assert result.exit_code == 1
    assert "unhealthy" in result.stdout


def test_lab_wait_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.lab_controller.wait", lambda **_kwargs: [])
    result = runner.invoke(app, ["lab", "wait", "--timeout", "1"])
    assert result.exit_code == 0
    assert "Lab is healthy" in result.stdout

    def fail(**_kwargs: object) -> None:
        raise LabError("timed out")

    monkeypatch.setattr("edl.cli.lab_controller.wait", fail)
    result = runner.invoke(app, ["lab", "wait"])
    assert result.exit_code == 1
    assert "timed out" in result.stdout


def test_lab_bootstrap_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.lab_controller.bootstrap", lambda: None)
    result = runner.invoke(app, ["lab", "bootstrap"])
    assert result.exit_code == 0
    assert "bootstrap complete" in result.stdout

    def fail() -> None:
        raise LabError("schema failed")

    monkeypatch.setattr("edl.cli.lab_controller.bootstrap", fail)
    result = runner.invoke(app, ["lab", "bootstrap"])
    assert result.exit_code == 2
    assert "schema failed" in result.stdout


def test_lab_reset_with_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("edl.cli.lab_controller.reset", lambda: calls.append("reset"))
    result = runner.invoke(app, ["lab", "reset", "--yes"])
    assert result.exit_code == 0
    assert calls == ["reset"]
    assert "Volumes deleted" in result.stdout


def test_lab_logs_forwards_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str | None, bool]] = []
    monkeypatch.setattr(
        "edl.cli.lab_controller.logs",
        lambda *, service, follow: calls.append((service, follow)),
    )
    result = runner.invoke(app, ["lab", "logs", "opensearch", "--no-follow"])
    assert result.exit_code == 0
    assert calls == [("opensearch", False)]


def test_ingest_identity_dry_run() -> None:
    result = runner.invoke(app, ["ingest", "identity", "--dry-run"])
    assert result.exit_code == 0
    assert "Identity Telemetry Ingest" in result.stdout
    assert "entra-signin" in result.stdout
    assert "entra-audit" in result.stdout
    assert "dry-run" in result.stdout


def test_ingest_identity_json() -> None:
    result = runner.invoke(app, ["ingest", "identity", "--dry-run", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["source"] for item in payload] == ["entra-signin", "entra-audit"]
    assert all(item["dry_run"] for item in payload)
    assert all(item["mode"] == "dry-run" for item in payload)


def test_ingest_identity_source_filter() -> None:
    result = runner.invoke(
        app,
        ["ingest", "identity", "--source", "entra-signin", "--dry-run", "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["source"] for item in payload] == ["entra-signin"]


def test_ingest_identity_reports_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise IngestError("unknown source")

    monkeypatch.setattr("edl.cli.run_ingest_domain", fail)
    result = runner.invoke(app, ["ingest", "identity", "--dry-run"])
    assert result.exit_code == 2
    assert "unknown source" in result.stdout


def test_ingest_identity_rejects_zero_batch_size() -> None:
    result = runner.invoke(
        app,
        ["ingest", "identity", "--dry-run", "--batch-size", "0"],
    )
    assert result.exit_code == 2


def test_ingest_endpoint_dry_run() -> None:
    result = runner.invoke(app, ["ingest", "endpoint", "--dry-run"])
    assert result.exit_code == 0
    assert "Endpoint Telemetry Ingest" in result.stdout
    assert "sysmon" in result.stdout
    assert "windows" in result.stdout
    assert "dry-run" in result.stdout


def test_ingest_endpoint_json() -> None:
    result = runner.invoke(app, ["ingest", "endpoint", "--dry-run", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["source"] for item in payload] == ["sysmon", "windows-security"]
    assert payload[0]["indices"] == ["edl-events-sysmon-2026.11.01"]
    assert payload[1]["indices"] == ["edl-events-windows-security-2026.11.01"]


def test_ingest_endpoint_source_filter() -> None:
    result = runner.invoke(
        app,
        ["ingest", "endpoint", "--source", "windows-security", "--dry-run", "--json"],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["source"] for item in payload] == ["windows-security"]


def test_ingest_cloud_dry_run() -> None:
    result = runner.invoke(app, ["ingest", "cloud", "--dry-run"])
    assert result.exit_code == 0
    assert "Cloud Telemetry Ingest" in result.stdout
    assert "aws-cloudtrail" in result.stdout
    assert "dry-run" in result.stdout


def test_ingest_cloud_json() -> None:
    result = runner.invoke(app, ["ingest", "cloud", "--dry-run", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["source"] for item in payload] == ["aws-cloudtrail"]
    assert payload[0]["indices"] == ["edl-events-aws-cloudtrail-2026.11.01"]


def _detection_result(passed: bool = True) -> DetectionResult:
    false_positives = 0 if passed else 1
    return DetectionResult(
        detection_id="DET-END-000",
        title="Reference Detection",
        path=Path("detections/endpoint/_template"),
        sample_size=3,
        positive_count=1,
        negative_count=1,
        benign_count=1,
        true_positives=1,
        false_negatives=0,
        false_positives=false_positives,
        true_negatives=2 - false_positives,
        precision=1.0 if passed else 0.5,
        recall=1.0,
        false_positive_rate=0.0 if passed else 0.5,
        latency_ms_p50=1.0,
        latency_ms_p95=2.0,
        matched_ids=("positive-001",),
        missed_ids=(),
        false_positive_ids=() if passed else ("benign-001",),
    )


def test_detection_test_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.run_detections", lambda *a, **k: [_detection_result()])
    result = runner.invoke(app, ["detection", "test", "--id", "DET-END-000"])
    assert result.exit_code == 0
    assert "Detection Fixture Replay" in result.stdout
    assert "DET-END-000" in result.stdout
    assert "passed" in result.stdout


def test_detection_test_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("edl.cli.run_detections", lambda *a, **k: [_detection_result()])
    result = runner.invoke(app, ["detection", "test", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload[0]["detection_id"] == "DET-END-000"
    assert payload[0]["passed"] is True


def test_detection_test_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "edl.cli.run_detections",
        lambda *a, **k: [_detection_result(passed=False)],
    )
    result = runner.invoke(app, ["detection", "test"])
    assert result.exit_code == 1
    assert "failed" in result.stdout


def test_detection_test_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise DetectionError("OpenSearch unavailable")

    monkeypatch.setattr("edl.cli.run_detections", fail)
    result = runner.invoke(app, ["detection", "test"])
    assert result.exit_code == 2
    assert "OpenSearch unavailable" in result.stdout


def test_detection_test_forwards_write_metrics(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake(*_args: object, **kwargs: object) -> list[DetectionResult]:
        captured.update(kwargs)
        return [_detection_result()]

    monkeypatch.setattr("edl.cli.run_detections", fake)
    result = runner.invoke(
        app,
        [
            "detection",
            "test",
            "--write-metrics",
            "--latency-runs",
            "2",
            "--include-templates",
        ],
    )
    assert result.exit_code == 0
    assert captured["write_metrics"] is True
    assert captured["latency_runs"] == 2
    assert captured["include_templates"] is True
