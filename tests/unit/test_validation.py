from __future__ import annotations

import json
from pathlib import Path

import pytest

from edl.validation import validate_repository


def _write_detection(
    root: Path,
    *,
    detection_id: str = "DET-IDN-001",
    domain: str = "identity",
    slug: str = "oauth-consent",
    positive_count: int = 1,
) -> Path:
    detection = root / "detections" / domain / slug
    (detection / "queries").mkdir(parents=True)
    (detection / "fixtures").mkdir()
    (detection / "tests").mkdir()

    (detection / "meta.yaml").write_text(
        f"""id: {detection_id}
title: OAuth consent grant
version: 1.0.0
status: tested
domain: {domain}
severity: high
hypothesis: An OAuth consent grant can indicate phishing or malicious app consent.
owner: detection-engineering
attack:
  - T1528
telemetry:
  - source: entra-audit
    event_class: audit
    required_fields:
      - operationName
      - initiatedBy
queries:
  opensearch: queries/opensearch.json
tests:
  positive: {positive_count}
  negative: 1
  benign: 1
false_positives:
  - Legitimate administrator consent
runbook: runbook.md
""",
        encoding="utf-8",
    )
    (detection / "rule.sigma.yml").write_text(
        """title: OAuth consent grant
id: 00000000-0000-4000-8000-000000000001
status: test
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    operationName: Add service principal
  condition: selection
level: high
""",
        encoding="utf-8",
    )
    (detection / "queries" / "opensearch.json").write_text(
        '{"query": {"match_all": {}}}\n', encoding="utf-8"
    )
    event = '{"event": {"id": "1"}, "source": "entra-audit", "synthetic": true}'
    for kind in ("positive", "negative", "benign"):
        count = positive_count if kind == "positive" else 1
        fixture = "[" + ",".join([event] * count) + "]"
        (detection / "fixtures" / f"{kind}.json").write_text(fixture, encoding="utf-8")
    (detection / "tests" / "test_detection.py").write_text(
        "def test_placeholder():\n    assert True\n", encoding="utf-8"
    )
    (detection / "runbook.md").write_text("Triage the consent grant.\n", encoding="utf-8")
    metrics = {
        "detection_id": detection_id,
        "measured_at": "2026-11-22T00:00:00Z",
        "sample_size": 1,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
        "latency_ms_p50": 0,
        "latency_ms_p95": 0,
        "method": "Reference fixture evaluation.",
        "limitations": ["Synthetic fixtures only."],
    }
    (detection / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (detection / "notes.md").write_text("Reference detection for tests.\n", encoding="utf-8")
    return detection


def _write_investigation(root: Path) -> Path:
    investigation = root / "investigations" / "01-identity-to-cloud"
    (investigation / "queries").mkdir(parents=True)
    (investigation / "evidence").mkdir()

    (investigation / "meta.yaml").write_text(
        """id: INV-001
title: Identity to cloud
version: 1.0.0
status: tested
domains:
  - identity
  - cloud
scenario: Synthetic OAuth consent leading to cloud role assumption.
hypothesis: A consent grant can precede cloud role assumption.
detections:
  - DET-IDN-001
owner: detection-engineering
evidence:
  - id: e1
    type: event
    source: entra-audit
    path: evidence/e1.json
    provenance: synthetic
timeline:
  - timestamp: "2026-11-01T09:00:00Z"
    event: Consent grant observed
    source: entra-audit
    evidence_id: e1
lessons:
  - The consent grant should be correlated with role assumption.
executive_summary: Synthetic reference investigation.
""",
        encoding="utf-8",
    )
    (investigation / "README.md").write_text("Synthetic scenario.\n", encoding="utf-8")
    (investigation / "timeline.md").write_text("Timeline.\n", encoding="utf-8")
    (investigation / "queries" / "opensearch.json").write_text(
        '{"query": {"match_all": {}}}\n', encoding="utf-8"
    )
    (investigation / "evidence" / "e1.json").write_text(
        '{"id": "e1", "synthetic": true}\n', encoding="utf-8"
    )
    (investigation / "response.md").write_text("Containment.\n", encoding="utf-8")
    (investigation / "lessons.md").write_text("Lessons.\n", encoding="utf-8")
    (investigation / "executive-summary.md").write_text("Summary.\n", encoding="utf-8")
    return investigation


def _write_source(root: Path, source_id: str = "entra-signin") -> Path:
    source_dir = root / "telemetry" / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    path = source_dir / f"{source_id}.yaml"
    path.write_text(
        f"""id: {source_id}
name: Microsoft Entra ID sign-in logs
provider: Microsoft
product: Entra ID
event_classes:
  - sign_in
schema_version: "1.0"
status: sampled
owner: detection-engineering
event_time_field: createdDateTime
ingest_time_field: ingest_time
timezone: UTC
ordering: unordered
dedup_key:
  - id
required_fields:
  - id
  - createdDateTime
known_gaps: []
""",
        encoding="utf-8",
    )
    return path


def _valid_repo(root: Path) -> None:
    _write_detection(root)
    _write_investigation(root)
    _write_source(root)


def test_valid_repository(tmp_path: Path) -> None:
    _valid_repo(tmp_path)
    report = validate_repository(tmp_path)
    assert report.ok, [issue.message for issue in report.errors]
    assert report.summary == {
        "detections": 1,
        "investigations": 1,
        "templates": 0,
        "telemetry_sources": 1,
        "errors": 0,
        "warnings": 0,
    }


def test_missing_fixture_fails(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "fixtures" / "benign.json").unlink()
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "fixture.missing" for issue in report.errors)


def test_fixture_count_mismatch_fails(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    meta = detection / "meta.yaml"
    meta.write_text(meta.read_text().replace("positive: 1", "positive: 2"), encoding="utf-8")
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "fixture.count" for issue in report.errors)


def test_id_path_mismatch_fails(tmp_path: Path) -> None:
    _write_detection(tmp_path, detection_id="DET-CLD-001")
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "domain" for issue in report.errors)
    assert any(issue.code == "path.domain" for issue in report.errors)


def test_duplicate_detection_id_fails(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_detection(tmp_path, slug="oauth-consent-copy")
    report = validate_repository(tmp_path)
    assert not report.ok
    assert len([issue for issue in report.errors if issue.code == "duplicate.id"]) >= 2


def test_unknown_detection_link_fails(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    meta = investigation / "meta.yaml"
    meta.write_text(meta.read_text().replace("DET-IDN-001", "DET-IDN-999"), encoding="utf-8")
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "detection.link" for issue in report.errors)


def test_duplicate_telemetry_source_id_fails(tmp_path: Path) -> None:
    _write_source(tmp_path)
    duplicate = tmp_path / "telemetry" / "sources" / "entra-signin-copy.yaml"
    duplicate.write_text((tmp_path / "telemetry" / "sources" / "entra-signin.yaml").read_text())
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "duplicate.id" for issue in report.errors)


def test_missing_telemetry_sample_fails(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    source.write_text(
        source.read_text()
        + """sample_data:
  path: lab/datasets/missing.json
  synthetic: true
  license: synthetic
  provenance: generated for test
""",
        encoding="utf-8",
    )
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "telemetry.sample" for issue in report.errors)


def test_missing_detection_files_fail(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "rule.sigma.yml").unlink()
    (detection / "runbook.md").unlink()
    (detection / "notes.md").unlink()
    (detection / "tests" / "test_detection.py").unlink()
    report = validate_repository(tmp_path)
    codes = {issue.code for issue in report.errors}
    assert {"file.rule", "file.runbook", "file.notes", "file.tests"} <= codes


def test_missing_and_empty_queries_fail(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "queries" / "opensearch.json").unlink()
    report = validate_repository(tmp_path)
    assert any(issue.code == "file.queries" for issue in report.errors)

    (detection / "queries").rmdir()
    report = validate_repository(tmp_path)
    assert any(issue.code == "file.queries" for issue in report.errors)


def test_query_path_errors_fail(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    meta = detection / "meta.yaml"
    meta.write_text(meta.read_text().replace("queries/opensearch.json", "../../escape.json"))
    report = validate_repository(tmp_path)
    assert any(issue.code == "query.path" for issue in report.errors)

    meta.write_text(meta.read_text().replace("../../escape.json", "queries/missing.json"))
    report = validate_repository(tmp_path)
    assert any(issue.code == "query.missing" for issue in report.errors)


def test_fixture_shape_and_schema_errors_fail(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "fixtures" / "positive.json").write_text("{}", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "fixture.shape" for issue in report.errors)

    event = '{"event": {"id": "1"}, "source": "entra-audit", "synthetic": true}'
    (detection / "fixtures" / "positive.json").write_text(f"[{event}]", encoding="utf-8")
    (detection / "fixtures" / "negative.json").write_text(
        '[{"event": {"id": "1"}}]', encoding="utf-8"
    )
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)


def test_metrics_errors_fail(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    metrics_path = detection / "metrics.json"
    metrics_path.write_text("{", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "metrics.invalid" for issue in report.errors)

    metrics_path.write_text('{"detection_id": "DET-IDN-001"}', encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)


def test_production_detection_requires_metrics_and_notes(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    meta = detection / "meta.yaml"
    meta.write_text(meta.read_text().replace("status: tested", "status: production"))
    (detection / "metrics.json").unlink()
    (detection / "notes.md").unlink()
    report = validate_repository(tmp_path)
    codes = {issue.code for issue in report.errors}
    assert {"file.metrics", "file.notes", "status.metrics", "status.notes"} <= codes


def test_sigma_missing_and_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_detection(tmp_path)
    monkeypatch.setattr("edl.validation.shutil.which", lambda _name: None)
    report = validate_repository(tmp_path, check_sigma=True)
    assert any(issue.code == "sigma.missing" for issue in report.errors)

    monkeypatch.setattr("edl.validation.shutil.which", lambda _name: "/bin/false")
    report = validate_repository(tmp_path, check_sigma=True)
    assert any(issue.code == "sigma" for issue in report.errors)


def test_investigation_missing_files_and_directories(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    for name in ("README.md", "timeline.md", "response.md", "lessons.md", "executive-summary.md"):
        (investigation / name).unlink()
    (investigation / "queries" / "opensearch.json").unlink()
    (investigation / "evidence" / "e1.json").unlink()
    report = validate_repository(tmp_path)
    codes = {issue.code for issue in report.errors}
    assert "file.queries" in codes
    assert "file.evidence" in codes
    assert any(code.startswith("file.") for code in codes)


def test_investigation_evidence_and_timeline_errors(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    meta = investigation / "meta.yaml"
    meta.write_text(
        meta.read_text()
        .replace("path: evidence/e1.json", "path: ../escape.json")
        .replace("path: ../escape.json", "path: evidence/missing.json")
        .replace("evidence_id: e1", "evidence_id: e2"),
        encoding="utf-8",
    )
    report = validate_repository(tmp_path)
    codes = {issue.code for issue in report.errors}
    assert "evidence.missing" in codes
    assert "timeline.evidence" in codes


def test_telemetry_schema_errors_and_load_error(tmp_path: Path) -> None:
    source = _write_source(tmp_path)
    source.write_text("id: [unterminated\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "telemetry.load" for issue in report.errors)

    source.write_text("id: bad\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)
    assert any(issue.code == "telemetry.source" for issue in report.errors)


def test_include_path_file_and_schema_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    detection = _write_detection(tmp_path)
    report = validate_repository(tmp_path, include_path=detection / "meta.yaml")
    assert report.ok
    assert report.summary["detections"] == 1

    monkeypatch.setattr("edl.validation.config.SCHEMAS_DIR", tmp_path / "missing-schemas")
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema.missing" for issue in report.errors)


def test_invalid_meta_yaml_fails(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "meta.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "meta" for issue in report.errors)


def test_invalid_detection_id_is_reported(tmp_path: Path) -> None:
    _write_detection(tmp_path, detection_id="BAD-001")
    report = validate_repository(tmp_path)
    assert any(issue.code == "id" for issue in report.errors)


def test_query_value_must_be_a_path_string(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    meta = detection / "meta.yaml"
    meta.write_text(
        meta.read_text().replace(
            "  opensearch: queries/opensearch.json",
            "  opensearch: 123",
        ),
        encoding="utf-8",
    )
    report = validate_repository(tmp_path)
    assert any(issue.code == "query.path" for issue in report.errors)


def test_fixture_invalid_json_is_reported(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    (detection / "fixtures" / "positive.json").write_text("{", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "fixture.invalid" for issue in report.errors)


def test_metrics_id_mismatch_is_reported(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    metrics = json.loads((detection / "metrics.json").read_text(encoding="utf-8"))
    metrics["detection_id"] = "DET-IDN-002"
    (detection / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "metrics.id" for issue in report.errors)


def test_unsafe_runbook_path_is_reported(tmp_path: Path) -> None:
    detection = _write_detection(tmp_path)
    meta = detection / "meta.yaml"
    meta.write_text(
        meta.read_text().replace("runbook: runbook.md", "runbook: ../../runbook.md"),
        encoding="utf-8",
    )
    report = validate_repository(tmp_path)
    assert any(issue.code == "runbook.path" for issue in report.errors)


def test_invalid_investigation_meta_is_reported(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    (investigation / "meta.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "meta" for issue in report.errors)


def test_investigation_non_mapping_items_are_ignored(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    meta = investigation / "meta.yaml"
    text = meta.read_text()
    text = text.replace(
        "    provenance: synthetic\n",
        "    provenance: synthetic\n  - not-a-mapping\n",
    )
    text = text.replace(
        "    evidence_id: e1\n",
        "    evidence_id: e1\n  - not-a-mapping\n",
    )
    meta.write_text(text, encoding="utf-8")
    report = validate_repository(tmp_path)
    assert not report.ok
    assert any(issue.code == "schema" for issue in report.errors)


def test_unsafe_evidence_path_is_reported(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    investigation = _write_investigation(tmp_path)
    meta = investigation / "meta.yaml"
    meta.write_text(
        meta.read_text().replace("path: evidence/e1.json", "path: ../../escape.json"),
        encoding="utf-8",
    )
    report = validate_repository(tmp_path)
    assert any(issue.code == "evidence.path" for issue in report.errors)


def test_invalid_schema_json_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_detection(tmp_path)
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "detection.schema.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr("edl.validation.config.SCHEMAS_DIR", schemas)
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema.invalid" for issue in report.errors)


def test_strict_validation_promotes_no_warnings_on_valid_repo(tmp_path: Path) -> None:
    _valid_repo(tmp_path)
    report = validate_repository(tmp_path, strict=True)
    assert report.ok
    assert report.summary["warnings"] == 0


def _write_exceptions(
    root: Path,
    *,
    detection_id: str = "DET-IDN-001",
    exception_id: str = "EXC-IDN-001-001",
    expires: str = "2027-05-31",
    duplicate: bool = False,
    invalid_type: bool = False,
    non_object: bool = False,
) -> Path:
    path = root / "detections" / "exceptions.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    exception = f"""  - id: {exception_id}
    detection_id: {detection_id}
    type: {"invalid" if invalid_type else "review-only"}
    owner: identity-platform
    reason: Approved application onboarding workflow requires review.
    scope:
      workflow: application-onboarding
    change_ticket: CHG-2026-0187
    created: "2026-11-24"
    expires: "{expires}"
    compensating_controls:
      - Require a change ticket and owner approval.
"""
    body = exception
    if duplicate:
        body += exception.replace(exception_id, exception_id)
    if non_object:
        body += "  - not-an-object\n"
    path.write_text(f"version: 1\nexceptions:\n{body}", encoding="utf-8")
    return path


def test_valid_exception_catalog(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path)
    report = validate_repository(tmp_path)
    assert report.ok, [issue.message for issue in report.errors]
    assert report.summary["warnings"] == 0


def test_exception_references_unknown_detection(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, detection_id="DET-IDN-999")
    report = validate_repository(tmp_path)
    assert any(issue.code == "exception.detection" for issue in report.errors)


def test_exception_duplicate_id(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, duplicate=True)
    report = validate_repository(tmp_path)
    assert any(issue.code == "exception.duplicate" for issue in report.errors)


def test_exception_expired_is_a_warning(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, expires="2020-01-01")
    report = validate_repository(tmp_path)
    assert report.ok
    assert any(issue.code == "exception.expired" for issue in report.warnings)


def test_exception_schema_error(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, invalid_type=True)
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)


def test_exception_invalid_date_is_schema_error(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, expires="not-a-date")
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)


def test_exception_non_object_entry(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    _write_exceptions(tmp_path, non_object=True)
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)


def test_exception_invalid_yaml(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    path = tmp_path / "detections" / "exceptions.yaml"
    path.write_text("exceptions: [unterminated\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "exception.load" for issue in report.errors)


def test_exception_catalog_requires_exceptions_list(tmp_path: Path) -> None:
    _write_detection(tmp_path)
    path = tmp_path / "detections" / "exceptions.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    report = validate_repository(tmp_path)
    assert any(issue.code == "schema" for issue in report.errors)
