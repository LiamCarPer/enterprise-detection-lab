from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from edl import config
from edl.detection import run_baseline
from edl.errors import DetectionError
from edl.loader import load_json

DETECTION_ID = "DET-END-001"
PACKAGE = config.ROOT / "detections" / "endpoint" / "encoded-powershell-non-powershell-parent"
POSITIVE = load_json(PACKAGE / "fixtures" / "positive.json")[0]
BENIGN = load_json(PACKAGE / "fixtures" / "benign.json")[0]


class FakeBaselineClient:
    def __init__(self, matched: set[str] | None = None) -> None:
        self.matched = matched or set()
        self.actions: list[tuple[str, dict[str, object]]] = []
        self.search_calls = 0
        self.deleted: list[str] = []
        self.closed = False

    def bulk(
        self,
        index: str,
        actions: list[tuple[str, dict[str, object]]],
        *,
        refresh: bool,
    ) -> None:
        self.actions = list(actions)
        self.index = index
        self.refresh = refresh

    def search(self, index: str, body: dict[str, object]) -> dict[str, object]:
        self.search_calls += 1
        hits = [{"_id": case_id} for case_id, _document in self.actions if case_id in self.matched]
        return {"hits": {"hits": hits}}

    def delete_matching(self, index_pattern: str) -> None:
        self.deleted.append(index_pattern)

    def close(self) -> None:
        self.closed = True


def _dataset(tmp_path: Path, *envelopes: object) -> Path:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(list(envelopes)), encoding="utf-8")
    return path


def test_run_baseline_measures_matches_and_cleans_up(tmp_path: Path) -> None:
    dataset = _dataset(tmp_path, POSITIVE, BENIGN)
    client = FakeBaselineClient({"baseline-001"})
    result = run_baseline(
        DETECTION_ID,
        dataset,
        client=client,  # type: ignore[arg-type]
        ingest_time=datetime(2026, 11, 23, tzinfo=UTC),
        latency_runs=2,
    )
    assert result.sample_size == 2
    assert result.matched_count == 1
    assert result.false_positive_rate == 0.5
    assert result.matched_ids == ("baseline-001",)
    assert client.search_calls == 2
    assert len(client.deleted) == 1
    assert client.deleted[0].startswith("edl-events-baseline-det-end-001-")


def test_run_baseline_accepts_query_override(tmp_path: Path) -> None:
    dataset = _dataset(tmp_path, POSITIVE)
    query = tmp_path / "query.json"
    query.write_text('{"query": {"match_all": {}}}', encoding="utf-8")
    client = FakeBaselineClient({"baseline-001"})
    result = run_baseline(
        DETECTION_ID,
        dataset,
        client=client,  # type: ignore[arg-type]
        query_path=query,
        latency_runs=1,
    )
    assert result.matched_count == 1


def test_run_baseline_rejects_unknown_detection(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="Detection not found"):
        run_baseline("DET-IDN-999", _dataset(tmp_path, BENIGN))


def test_run_baseline_rejects_missing_dataset(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="not found"):
        run_baseline(DETECTION_ID, tmp_path / "missing.json")


def test_run_baseline_rejects_empty_dataset(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="non-empty array"):
        run_baseline(DETECTION_ID, _dataset(tmp_path))


def test_run_baseline_rejects_non_synthetic_event(tmp_path: Path) -> None:
    envelope = dict(POSITIVE)
    envelope["synthetic"] = False
    with pytest.raises(DetectionError, match="must be marked synthetic"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, envelope))


def test_run_baseline_rejects_undeclared_source(tmp_path: Path) -> None:
    envelope = dict(POSITIVE)
    envelope["source"] = "aws-cloudtrail"
    with pytest.raises(DetectionError, match="not declared"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, envelope))


def test_run_baseline_rejects_invalid_latency(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="latency_runs"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, BENIGN), latency_runs=0)


def test_run_baseline_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(DetectionError):
        run_baseline(DETECTION_ID, path)


def test_run_baseline_rejects_non_object_event(tmp_path: Path) -> None:
    envelope = {"event": "bad", "source": "sysmon", "synthetic": True}
    with pytest.raises(DetectionError, match="event must be an object"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, envelope))


def test_run_baseline_rejects_unknown_source_contract(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="unknown telemetry source"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, POSITIVE), sources={})


def test_run_baseline_rejects_normalization_error(tmp_path: Path) -> None:
    envelope = dict(POSITIVE)
    event = dict(envelope["event"])
    del event["Channel"]
    envelope["event"] = event
    with pytest.raises(DetectionError, match="missing required field"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, envelope))


def test_run_baseline_rejects_duplicate_detection_ids(tmp_path: Path) -> None:
    for slug in ("first", "second"):
        path = tmp_path / "detections" / "identity" / slug
        path.mkdir(parents=True)
        (path / "meta.yaml").write_text("id: DET-END-001\n", encoding="utf-8")
    with pytest.raises(DetectionError, match="Multiple detections"):
        run_baseline(DETECTION_ID, tmp_path / "missing.json", root=tmp_path, sources={})


def test_run_baseline_wraps_invalid_source_contract(tmp_path: Path) -> None:
    source_dir = tmp_path / "telemetry" / "sources"
    source_dir.mkdir(parents=True)
    (source_dir / "bad.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(DetectionError):
        run_baseline(DETECTION_ID, _dataset(tmp_path, POSITIVE), root=tmp_path)


def test_run_baseline_closes_owned_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeBaselineClient({"baseline-001"})
    monkeypatch.setattr("edl.detection.OpenSearchClient", lambda: client)
    result = run_baseline(
        DETECTION_ID,
        _dataset(tmp_path, POSITIVE),
        latency_runs=1,
    )
    assert result.matched_count == 1
    assert client.closed


def test_run_baseline_rejects_non_object_fixture(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="baseline event 1 must be an object"):
        run_baseline(DETECTION_ID, _dataset(tmp_path, "bad"))
