from __future__ import annotations

import json
from pathlib import Path

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
