from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from edl import config
from edl.detection import (
    build_search_body,
    extract_hit_ids,
    load_detection_package,
    run_detection,
    run_detections,
)
from edl.errors import DetectionError
from edl.telemetry import load_sources

TEMPLATE = config.ROOT / "detections" / "endpoint" / "_template"


def _sources() -> dict[str, object]:
    return {source.id: source for source in load_sources(config.ROOT)}


def _copy_template(tmp_path: Path, name: str = "detection") -> Path:
    target = tmp_path / name
    shutil.copytree(TEMPLATE, target)
    return target


class FakeDetectionClient:
    def __init__(self, matched_kinds: tuple[str, ...] = ("positive",)) -> None:
        self.matched_kinds = matched_kinds
        self.actions: list[tuple[str, dict[str, object]]] = []
        self.search_calls = 0
        self.last_body: dict[str, object] = {}
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
        self.last_body = body
        hits = [
            {"_id": case_id}
            for case_id, _document in self.actions
            if case_id.split("-")[0] in self.matched_kinds
        ]
        return {"hits": {"hits": hits}}

    def delete_matching(self, index_pattern: str) -> None:
        self.deleted.append(index_pattern)

    def close(self) -> None:
        self.closed = True


def _mutate_meta(path: Path, old: str, new: str) -> None:
    meta = path / "meta.yaml"
    meta.write_text(meta.read_text().replace(old, new), encoding="utf-8")


def _write_fixture(path: Path, kind: str, payload: object) -> None:
    (path / "fixtures" / f"{kind}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_load_detection_package_normalizes_fixtures() -> None:
    package = load_detection_package(
        TEMPLATE,
        _sources(),  # type: ignore[arg-type]
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert package.detection_id == "DET-END-000"
    assert package.title == "Reference Detection — Whoami Execution"
    assert package.query["query"]
    assert [case.kind for case in package.cases] == ["positive", "negative", "benign"]
    assert all(case.source == "sysmon" for case in package.cases)
    assert package.cases[0].event.document["event_class"] == "process_creation"
    assert package.cases[0].event.document["dedup_origin"] == "declared"


def test_load_detection_package_rejects_missing_query(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    _mutate_meta(path, "queries:\n  opensearch: queries/opensearch.json", "queries: {}")
    with pytest.raises(DetectionError, match="meta.queries.opensearch"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_query_without_query_key(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "queries" / "opensearch.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DetectionError, match="query field"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_empty_telemetry(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    meta = path / "meta.yaml"
    text = meta.read_text()
    meta.write_text(
        text[: text.index("telemetry:")] + "telemetry: []\n" + text[text.index("queries:") :],
        encoding="utf-8",
    )
    with pytest.raises(DetectionError, match="meta.telemetry"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_non_synthetic_fixture(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    positive = json.loads((path / "fixtures" / "positive.json").read_text())
    positive[0]["synthetic"] = False
    _write_fixture(path, "positive", positive)
    with pytest.raises(DetectionError, match="must be marked synthetic"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_undeclared_source(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    positive = json.loads((path / "fixtures" / "positive.json").read_text())
    positive[0]["source"] = "aws-cloudtrail"
    _write_fixture(path, "positive", positive)
    with pytest.raises(DetectionError, match="not declared in meta.telemetry"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_unknown_source(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    _mutate_meta(path, "  - source: sysmon", "  - source: missing-source")
    for kind in ("positive", "negative", "benign"):
        fixture = json.loads((path / "fixtures" / f"{kind}.json").read_text())
        fixture[0]["source"] = "missing-source"
        _write_fixture(path, kind, fixture)
    with pytest.raises(DetectionError, match="unknown telemetry source"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "non-empty array"),
        ({"event": {}}, "must be a non-empty array"),
        (["not-an-object"], "must be an object"),
        ([{"event": "bad", "source": "sysmon", "synthetic": True}], "event must be an object"),
    ],
)
def test_load_detection_package_rejects_bad_fixture_shape(
    tmp_path: Path, payload: object, message: str
) -> None:
    path = _copy_template(tmp_path)
    _write_fixture(path, "positive", payload)
    with pytest.raises(DetectionError, match=message):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("id: DET-END-000", "id: ''", "meta.id"),
        ("title: Reference Detection — Whoami Execution", "title: ''", "meta.title"),
    ],
)
def test_load_detection_package_requires_identity(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    path = _copy_template(tmp_path)
    _mutate_meta(path, old, new)
    with pytest.raises(DetectionError, match=message):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_wraps_invalid_meta(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "meta.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(DetectionError):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_build_search_body_uses_larger_existing_size() -> None:
    assert build_search_body({"query": {"match_all": {}}, "size": 20}, 3)["size"] == 20
    assert build_search_body({"query": {"match_all": {}}}, 3)["size"] == 3
    assert build_search_body({"query": {"match_all": {}}, "size": "bad"}, 3)["size"] == 3
    assert build_search_body({"query": {"match_all": {}}}, 3)["track_total_hits"] is True


def test_extract_hit_ids_ignores_malformed_items() -> None:
    assert extract_hit_ids({"hits": {"hits": [1, {"_id": "positive-001"}]}}) == {"positive-001"}


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({}, "no hits object"),
        ({"hits": {}}, "no hits array"),
    ],
)
def test_extract_hit_ids_rejects_bad_response(response: dict[str, object], message: str) -> None:
    with pytest.raises(DetectionError, match=message):
        extract_hit_ids(response)


def test_run_detection_passes_and_cleans_up() -> None:
    client = FakeDetectionClient()
    result = run_detection(
        TEMPLATE,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        latency_runs=3,
    )
    assert result.passed
    assert result.sample_size == 3
    assert result.true_positives == 1
    assert result.false_negatives == 0
    assert result.false_positives == 0
    assert result.true_negatives == 2
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.false_positive_rate == 0.0
    assert result.latency_ms_p50 >= 0
    assert result.latency_ms_p95 >= 0
    assert result.matched_ids == ("positive-001",)
    assert client.search_calls == 3
    assert client.last_body["size"] == 3
    assert client.last_body["track_total_hits"] is True
    assert len(client.deleted) == 1
    assert client.deleted[0].startswith("edl-events-detect-det-end-000-")


def test_run_detection_fails_on_false_positive() -> None:
    client = FakeDetectionClient(matched_kinds=("positive", "benign"))
    result = run_detection(
        TEMPLATE,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert not result.passed
    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.true_negatives == 1
    assert result.precision == 0.5
    assert result.false_positive_ids == ("benign-001",)


def test_run_detection_fails_on_missed_positive() -> None:
    client = FakeDetectionClient(matched_kinds=())
    result = run_detection(
        TEMPLATE,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert not result.passed
    assert result.true_positives == 0
    assert result.false_negatives == 1
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.missed_ids == ("positive-001",)


def test_run_detection_writes_metrics(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "metrics.json").unlink()
    client = FakeDetectionClient()
    result = run_detection(
        path,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
        write_metrics=True,
    )
    assert result.passed
    metrics = json.loads((path / "metrics.json").read_text())
    assert metrics["detection_id"] == "DET-END-000"
    assert metrics["sample_size"] == 3
    assert metrics["method"].startswith("Synthetic fixture replay")
    assert len(metrics["limitations"]) == 3


def test_run_detection_does_not_write_metrics_on_failure(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "metrics.json").unlink()
    client = FakeDetectionClient(matched_kinds=("positive", "negative"))
    result = run_detection(
        path,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
        write_metrics=True,
    )
    assert not result.passed
    assert not (path / "metrics.json").exists()


def test_run_detection_closes_owned_client(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeDetectionClient()
    monkeypatch.setattr("edl.detection.OpenSearchClient", lambda: client)
    result = run_detection(
        TEMPLATE,
        sources=_sources(),  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert result.passed
    assert client.closed


def test_run_detection_rejects_invalid_latency_runs() -> None:
    with pytest.raises(DetectionError, match="latency_runs"):
        run_detection(TEMPLATE, sources=_sources(), latency_runs=0)  # type: ignore[arg-type]


def test_run_detections_explicit_template() -> None:
    client = FakeDetectionClient()
    results = run_detections(
        config.ROOT,
        detection_id="DET-END-000",
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert [result.detection_id for result in results] == ["DET-END-000"]
    assert results[0].passed


def test_run_detections_unknown_id() -> None:
    with pytest.raises(DetectionError, match="Detection not found"):
        run_detections(config.ROOT, detection_id="DET-IDN-999")


def test_run_detections_no_detections(tmp_path: Path) -> None:
    shutil.copytree(config.ROOT / "telemetry", tmp_path / "telemetry")
    with pytest.raises(DetectionError, match="No detections found"):
        run_detections(tmp_path)


def test_run_detections_executes_non_template_packages(tmp_path: Path) -> None:
    shutil.copytree(config.ROOT / "telemetry", tmp_path / "telemetry")
    shutil.copytree(TEMPLATE, tmp_path / "detections" / "endpoint" / "reference")
    client = FakeDetectionClient()
    results = run_detections(
        tmp_path,
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert [result.detection_id for result in results] == ["DET-END-000"]
    assert results[0].passed


def test_run_detections_closes_owned_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shutil.copytree(config.ROOT / "telemetry", tmp_path / "telemetry")
    shutil.copytree(TEMPLATE, tmp_path / "detections" / "endpoint" / "reference")
    client = FakeDetectionClient()
    monkeypatch.setattr("edl.detection.OpenSearchClient", lambda: client)
    results = run_detections(tmp_path, latency_runs=2)
    assert results[0].passed
    assert client.closed


def test_load_detection_package_rejects_queries_not_object(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    _mutate_meta(
        path,
        "queries:\n  opensearch: queries/opensearch.json",
        "queries: []",
    )
    with pytest.raises(DetectionError, match="meta.queries"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_missing_query_file(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "queries" / "opensearch.json").unlink()
    with pytest.raises(DetectionError, match="OpenSearch query not found"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_invalid_query_json(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "queries" / "opensearch.json").write_text("{", encoding="utf-8")
    with pytest.raises(DetectionError):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_telemetry_without_source(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    meta = path / "meta.yaml"
    text = meta.read_text()
    meta.write_text(
        text[: text.index("telemetry:")]
        + "telemetry:\n  - event_class: process_creation\n"
        + text[text.index("queries:") :],
        encoding="utf-8",
    )
    with pytest.raises(DetectionError, match="no source"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_missing_fixture(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "fixtures" / "benign.json").unlink()
    with pytest.raises(DetectionError, match="fixture not found"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_rejects_invalid_fixture_json(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    (path / "fixtures" / "positive.json").write_text("{", encoding="utf-8")
    with pytest.raises(DetectionError):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_load_detection_package_wraps_normalization_error(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    positive = json.loads((path / "fixtures" / "positive.json").read_text())
    del positive[0]["event"]["Channel"]
    _write_fixture(path, "positive", positive)
    with pytest.raises(DetectionError, match="missing required field"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_percentile_rejects_empty_values() -> None:
    from edl.detection import _percentile

    with pytest.raises(DetectionError, match="no samples"):
        _percentile([], 0.5)


def test_run_detection_wraps_invalid_source_contract(tmp_path: Path) -> None:
    source_dir = tmp_path / "telemetry" / "sources"
    source_dir.mkdir(parents=True)
    (source_dir / "bad.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(DetectionError):
        run_detection(TEMPLATE, root=tmp_path)


def test_run_detections_wraps_invalid_source_contract(tmp_path: Path) -> None:
    source_dir = tmp_path / "telemetry" / "sources"
    source_dir.mkdir(parents=True)
    (source_dir / "bad.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(DetectionError):
        run_detections(tmp_path)


def test_run_detections_wraps_invalid_detection_meta(tmp_path: Path) -> None:
    shutil.copytree(config.ROOT / "telemetry", tmp_path / "telemetry")
    bad = tmp_path / "detections" / "endpoint" / "bad"
    bad.mkdir(parents=True)
    (bad / "meta.yaml").write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(DetectionError):
        run_detections(tmp_path)


def test_run_detections_includes_templates_when_requested() -> None:
    client = FakeDetectionClient()
    results = run_detections(
        config.ROOT,
        include_templates=True,
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert {result.detection_id for result in results} == {
        "DET-END-000",
        "DET-IDN-001",
        "DET-IDN-002",
        "DET-IDN-003",
        "DET-END-001",
        "DET-END-002",
        "DET-CLD-001",
        "DET-CLD-002",
        "DET-SAA-001",
        "DET-SAA-002",
        "DET-NET-001",
        "DET-NET-002",
        "DET-K8S-001",
        "DET-K8S-002",
    }
    assert all(result.passed for result in results)


CORRELATION = config.ROOT / "detections" / "identity" / "risky-signin-then-service-principal-owner"


def _copy_correlation(tmp_path: Path) -> Path:
    target = tmp_path / "correlation"
    shutil.copytree(CORRELATION, target)
    return target


def _replace_correlation(path: Path, replacement: str) -> None:
    meta = path / "meta.yaml"
    text = meta.read_text()
    start = text.index("correlation:")
    end = text.index("tests:")
    meta.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


def test_correlation_detection_evaluates_scenarios() -> None:
    client = FakeDetectionClient(matched_kinds=("positive", "negative", "benign"))
    result = run_detection(
        CORRELATION,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert result.evaluation_unit == "scenario"
    assert result.sample_size == 6
    assert result.positive_count == 2
    assert result.negative_count == 2
    assert result.benign_count == 2
    assert result.true_positives == 2
    assert result.false_negatives == 0
    assert result.false_positives == 0
    assert result.true_negatives == 4
    assert result.matched_ids == ("pos-1", "pos-2")


def test_correlation_detection_missing_group_field_fails(tmp_path: Path) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(
        path,
        "correlation:\n"
        "  window_seconds: 1800\n"
        "  group_by:\n"
        "    - missing_field\n"
        "  steps:\n"
        "    - source: entra-signin\n"
        "      event_class: sign_in\n"
        "    - source: entra-audit\n"
        "      event_class: audit\n",
    )
    client = FakeDetectionClient(matched_kinds=("positive", "negative", "benign"))
    result = run_detection(
        path,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
    )
    assert not result.passed
    assert result.true_positives == 0
    assert result.false_negatives == 2


def test_correlation_metrics_use_scenario_unit(tmp_path: Path) -> None:
    path = _copy_correlation(tmp_path)
    (path / "metrics.json").unlink()
    client = FakeDetectionClient(matched_kinds=("positive", "negative", "benign"))
    result = run_detection(
        path,
        sources=_sources(),  # type: ignore[arg-type]
        client=client,  # type: ignore[arg-type]
        latency_runs=2,
        write_metrics=True,
    )
    assert result.passed
    metrics = json.loads((path / "metrics.json").read_text())
    assert metrics["evaluation_unit"] == "scenario"
    assert metrics["sample_size"] == 6


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("correlation: []\n", "meta.correlation"),
        (
            "correlation:\n"
            "  window_seconds: 0\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "window_seconds",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by: []\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "group_by",
        ),
        (
            "correlation:\n  window_seconds: 1800\n  group_by:\n    - user\n  steps: []\n",
            "at least two steps",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - bad\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "step 1 must be an object",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: missing-source\n"
            "      event_class: sign_in\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "not declared",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: ''\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "event_class",
        ),
    ],
)
def test_correlation_spec_validation(tmp_path: Path, replacement: str, message: str) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(path, replacement)
    with pytest.raises(DetectionError, match=message):
        load_detection_package(path, _sources())  # type: ignore[arg-type]
