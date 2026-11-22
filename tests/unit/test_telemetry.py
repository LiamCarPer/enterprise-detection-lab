from __future__ import annotations

from pathlib import Path

from edl.telemetry import (
    TelemetrySource,
    ensure_unique_source_ids,
    matrix_is_current,
    render_matrix,
    validate_source_shape,
    write_matrix,
)


def _source(source_id: str = "entra-signin") -> TelemetrySource:
    return TelemetrySource(
        path=Path(f"{source_id}.yaml"),
        data={
            "id": source_id,
            "name": "Microsoft Entra ID sign-in logs",
            "event_classes": ["sign_in"],
            "event_time_field": "createdDateTime",
            "ingest_time_field": "ingest_time",
            "dedup_key": ["id"],
            "status": "sampled",
        },
    )


def test_render_matrix_is_deterministic() -> None:
    first = render_matrix([_source()])
    second = render_matrix([_source()])
    assert first == second
    assert "entra-signin" in first
    assert "createdDateTime" in first
    assert "ingest_time" in first


def test_matrix_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "telemetry-matrix.md"
    sources = [_source()]
    write_matrix(target, sources)
    assert matrix_is_current(target, sources)


def test_duplicate_source_ids() -> None:
    assert ensure_unique_source_ids([_source("a"), _source("a"), _source("b")]) == ["a"]


def test_source_shape_errors() -> None:
    source = TelemetrySource(
        path=Path("bad.yaml"),
        data={"id": "", "event_time_field": "", "ingest_time_field": "", "dedup_key": []},
    )
    errors = validate_source_shape(source)
    assert len(errors) == 4
