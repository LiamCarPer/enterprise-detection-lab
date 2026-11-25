from __future__ import annotations

import json
from pathlib import Path

import pytest

from edl.errors import DetectionError
from edl.metrics import (
    load_detection_metrics,
    metrics_report_is_current,
    render_metrics_report,
    write_metrics_report,
)

DETECTIONS = {
    "DET-CLD-001",
    "DET-CLD-002",
    "DET-END-001",
    "DET-END-002",
    "DET-IDN-001",
    "DET-IDN-002",
    "DET-IDN-003",
    "DET-SAA-001",
    "DET-SAA-002",
    "DET-NET-001",
    "DET-NET-002",
    "DET-K8S-001",
    "DET-K8S-002",
    "DET-SAA-003",
    "DET-SAA-004",
    "DET-SAA-005",
    "DET-SAA-006",
    "DET-SAA-007",
}


def _package(tmp_path: Path, **overrides: object) -> Path:
    path = tmp_path / "detections" / "identity" / "test"
    path.mkdir(parents=True)
    meta = {
        "id": "DET-IDN-001",
        "title": "Test Detection",
        "domain": "identity",
        "status": "tested",
    }
    metrics = {
        "detection_id": "DET-IDN-001",
        "measured_at": "2026-11-23T00:00:00Z",
        "sample_size": 3,
        "precision": 1.0,
        "recall": 1.0,
        "false_positive_rate": 0.0,
        "latency_ms_p50": 1.0,
        "latency_ms_p95": 2.0,
        "method": "Synthetic fixture replay.",
        "limitations": ["Synthetic fixtures only."],
    }
    for key, value in overrides.items():
        if key.startswith("meta_"):
            meta[key.removeprefix("meta_")] = value
        else:
            metrics[key] = value
    meta_text = "\n".join(f"{key}: {value}" for key, value in meta.items()) + "\n"
    (path / "meta.yaml").write_text(meta_text, encoding="utf-8")
    (path / "metrics.json").write_text(json.dumps(metrics), encoding="utf-8")
    return path


def test_load_detection_metrics_from_repository() -> None:
    metrics = load_detection_metrics()
    assert {item.detection_id for item in metrics} == DETECTIONS
    assert {item.detection_id: item.sample_size for item in metrics}["DET-IDN-003"] == 6
    assert {item.detection_id: item.sample_size for item in metrics}["DET-SAA-003"] == 6
    assert {item.detection_id: item.sample_size for item in metrics}["DET-SAA-004"] == 12
    assert {item.detection_id: item.sample_size for item in metrics}["DET-SAA-005"] == 7
    assert {item.detection_id: item.sample_size for item in metrics}["DET-SAA-006"] == 6
    assert {item.detection_id: item.sample_size for item in metrics}["DET-SAA-007"] == 8
    assert all(
        item.sample_size == 15
        for item in metrics
        if item.detection_id
        not in {
            "DET-IDN-003",
            "DET-SAA-003",
            "DET-SAA-004",
            "DET-SAA-005",
            "DET-SAA-006",
            "DET-SAA-007",
        }
    )
    assert [item.detection_id for item in metrics] == sorted(DETECTIONS)
    assert all(item.path.is_relative_to("detections") for item in metrics)


def test_render_and_check_metrics_report(tmp_path: Path) -> None:
    metrics = load_detection_metrics()
    report = render_metrics_report(metrics)
    assert "Event-level cases: 180" in report
    assert "Scenario-level cases: 45" in report
    assert "DET-IDN-001" in report
    assert "Synthetic fixture replay" in report
    assert "not production measurements" in report

    path = tmp_path / "detection-metrics.md"
    assert not metrics_report_is_current(path, metrics)
    write_metrics_report(path, metrics)
    assert metrics_report_is_current(path, metrics)
    path.write_text("stale", encoding="utf-8")
    assert not metrics_report_is_current(path, metrics)


def test_load_detection_metrics_requires_metrics(tmp_path: Path) -> None:
    path = tmp_path / "detections" / "identity" / "test"
    path.mkdir(parents=True)
    (path / "meta.yaml").write_text(
        "id: DET-IDN-001\ntitle: Test Detection\ndomain: identity\nstatus: tested\n",
        encoding="utf-8",
    )
    with pytest.raises(DetectionError):
        load_detection_metrics(tmp_path)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"meta_id": ""}, "meta.id"),
        ({"meta_title": ""}, "meta.title"),
        ({"meta_domain": ""}, "meta.domain"),
        ({"meta_status": ""}, "meta.status"),
        ({"sample_size": "3"}, "sample_size"),
        ({"measured_at": ""}, "measured_at"),
        ({"method": ""}, "method"),
        ({"limitations": "bad"}, "limitations"),
        ({"precision": "1.0"}, "precision"),
        ({"evaluation_unit": "invalid"}, "evaluation_unit"),
    ],
)
def test_load_detection_metrics_rejects_invalid_package(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    _package(tmp_path, **overrides)
    with pytest.raises(DetectionError, match=message):
        load_detection_metrics(tmp_path)


def test_load_detection_metrics_rejects_non_object(tmp_path: Path) -> None:
    path = _package(tmp_path)
    (path / "metrics.json").write_text("[]", encoding="utf-8")
    with pytest.raises(DetectionError, match="must be an object"):
        load_detection_metrics(tmp_path)


def test_load_detection_metrics_rejects_empty_repository(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="No detection metrics"):
        load_detection_metrics(tmp_path)
