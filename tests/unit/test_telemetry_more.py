from __future__ import annotations

from pathlib import Path

import pytest

from edl.errors import ValidationError
from edl.telemetry import (
    TelemetrySource,
    load_sources,
    matrix_is_current,
    render_matrix,
    source_license,
    source_path,
    source_provenance,
    validate_source_shape,
)
from edl.utils import sha256_file


def _source(data: dict[str, object] | None = None) -> TelemetrySource:
    payload: dict[str, object] = {
        "id": "entra-signin",
        "name": "Entra sign-in",
        "event_classes": ["sign_in"],
        "event_time_field": "createdDateTime",
        "ingest_time_field": "ingest_time",
        "dedup_key": ["id"],
        "status": "sampled",
    }
    if data:
        payload.update(data)
    return TelemetrySource(Path("entra-signin.yaml"), payload)


def test_render_empty_matrix() -> None:
    matrix = render_matrix([])
    assert "_none_" in matrix
    assert "Time and identity rules" in matrix


def test_matrix_is_current_false_for_missing_and_stale(tmp_path: Path) -> None:
    target = tmp_path / "matrix.md"
    assert not matrix_is_current(target, [_source()])
    target.write_text("stale", encoding="utf-8")
    assert not matrix_is_current(target, [_source()])


def test_source_shape_reports_sample_path() -> None:
    source = _source()
    source.data["sample_data"] = {"path": ""}
    errors = validate_source_shape(source)
    assert "sample_data.path is empty" in errors


def test_source_path_license_and_provenance() -> None:
    source = _source()
    assert source_path(Path("/repo"), source) == Path("/repo/__none__")
    assert source_license(source) == ""
    assert source_provenance(source) == ""

    source.data["sample_data"] = {
        "path": "lab/sample.json",
        "license": "synthetic",
        "provenance": "generated",
    }
    assert source_path(Path("/repo"), source) == Path("/repo/lab/sample.json")
    assert source_license(source) == "synthetic"
    assert source_provenance(source) == "generated"

    source.data["sample_data"] = {"path": 123}
    assert source_path(Path("/repo"), source) == Path("/repo/__none__")


def test_load_sources_round_trip(tmp_path: Path) -> None:
    source_dir = tmp_path / "telemetry" / "sources"
    source_dir.mkdir(parents=True)
    (source_dir / "entra-signin.yaml").write_text(
        """id: entra-signin
name: Entra sign-in
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
known_gaps: []
""",
        encoding="utf-8",
    )
    sources = load_sources(tmp_path)
    assert len(sources) == 1
    assert sources[0].id == "entra-signin"
    assert sha256_file(source_dir / "entra-signin.yaml")


def test_load_sources_reports_invalid_yaml(tmp_path: Path) -> None:
    source_dir = tmp_path / "telemetry" / "sources"
    source_dir.mkdir(parents=True)
    (source_dir / "bad.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_sources(tmp_path)


def test_render_matrix_handles_missing_fields() -> None:
    matrix = render_matrix([TelemetrySource(Path("minimal.yaml"), {"id": "minimal"})])
    assert "| minimal |  |  |  |  |  |  |" in matrix
