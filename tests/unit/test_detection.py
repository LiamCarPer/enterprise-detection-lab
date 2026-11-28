from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from edl import config
from edl.detection import (
    CanonicalEvent,
    CorrelationSpec,
    CorrelationStep,
    DetectionCase,
    ExistsFilter,
    FilterGroup,
    StepFilters,
    _correlation_hit,
    _match_values,
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


def test_load_detection_package_ignores_non_mapping_telemetry_entries(tmp_path: Path) -> None:
    path = _copy_template(tmp_path)
    _mutate_meta(path, "queries:", "  - not-a-mapping\nqueries:")
    package = load_detection_package(path, _sources())  # type: ignore[arg-type]
    assert package.detection_id == "DET-END-000"


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
        "DET-IDN-004",
        "DET-IDN-005",
        "DET-IDN-006",
        "DET-IDN-007",
        "DET-IDN-008",
        "DET-IDN-009",
        "DET-IDN-010",
        "DET-IDN-011",
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
        "DET-SAA-003",
        "DET-SAA-004",
        "DET-SAA-005",
        "DET-SAA-006",
        "DET-SAA-007",
        "DET-SAA-008",
        "DET-SAA-009",
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
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields: mailbox\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "match_fields",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      window_seconds: 0\n",
            "window_seconds",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      window_seconds: 60\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "step 1",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      valid_until_field: expires_on\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "only supported on exclusion",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n"
            "      valid_until_field: ''\n",
            "non-empty string",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n"
            "      min_count: 0\n",
            "min_count",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      min_count: 2\n",
            "only supported on exclusion",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      distinct_by: approver\n",
            "only supported on exclusion",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n"
            "      distinct_by: ''\n",
            "non-empty string",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_any_fields: mailbox\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "match_any_fields",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      exclude: maybe\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "exclude",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      exclude: true\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n",
            "precede",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n"
            "      match_fields:\n"
            "        - mailbox\n",
            "established",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_changed_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n",
            "only supported on non-exclude",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      match_changed_fields: src_ip\n",
            "match_changed_fields",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      match_changed_fields:\n"
            "        - src_ip\n",
            "established",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_fields:\n"
            "        - user\n"
            "        - src_ip\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      match_fields:\n"
            "        - user\n"
            "        - src_ip\n"
            "      match_changed_fields:\n"
            "        - src_ip\n",
            "overlap",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      match_any_fields:\n"
            "        - user\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n"
            "      match_any_fields:\n"
            "        - mailbox\n",
            "established",
        ),
        (
            "correlation:\n"
            "  window_seconds: 1800\n"
            "  group_by:\n"
            "    - user\n"
            "  steps:\n"
            "    - source: entra-signin\n"
            "      event_class: sign_in\n"
            "      exclude: true\n"
            "    - source: entra-audit\n"
            "      event_class: audit\n"
            "      exclude: true\n",
            "at least one non-exclude",
        ),
    ],
)
def test_correlation_spec_validation(tmp_path: Path, replacement: str, message: str) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(path, replacement)
    with pytest.raises(DetectionError, match=message):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def _make_case(
    case_id: str,
    source: str,
    event_class: str,
    event_time: datetime,
    document: dict[str, object],
) -> DetectionCase:
    return DetectionCase(
        case_id=case_id,
        kind="positive",
        source=source,
        event=CanonicalEvent(
            source=source,
            event_class=event_class,
            event_time=event_time,
            ingest_time=event_time,
            document=document,
            dedup_id=case_id,
        ),
        scenario="scenario",
    )


def _filter_value(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _filters(
    all_conditions: dict[str, object] | None = None,
    any_of: list[dict[str, object]] | None = None,
) -> StepFilters:
    return StepFilters(
        all=FilterGroup(
            tuple((field, _filter_value(value)) for field, value in (all_conditions or {}).items())
        )
        if all_conditions
        else None,
        any_of=tuple(
            FilterGroup(tuple((field, _filter_value(value)) for field, value in group.items()))
            for group in (any_of or [])
        ),
    )


def _step(
    source: str,
    event_class: str,
    *,
    filters: StepFilters | None = None,
    match_fields: tuple[str, ...] = (),
    match_any_fields: tuple[str, ...] = (),
    exclude: bool = False,
    window_seconds: int | None = None,
    valid_until_field: str | None = None,
    min_count: int = 1,
    distinct_by: str | None = None,
    match_changed_fields: tuple[str, ...] = (),
) -> CorrelationStep:
    return CorrelationStep(
        source=source,
        event_class=event_class,
        match_fields=match_fields,
        match_any_fields=match_any_fields,
        filters=filters or StepFilters(),
        exclude=exclude,
        window_seconds=window_seconds,
        valid_until_field=valid_until_field,
        min_count=min_count,
        distinct_by=distinct_by,
        match_changed_fields=match_changed_fields,
    )


def _spec(*steps: CorrelationStep, window_seconds: int = 60) -> CorrelationSpec:
    return CorrelationSpec(
        window_seconds=window_seconds,
        group_by=("user",),
        steps=tuple(steps),
    )


def test_correlation_filter_scalar_on_first_step() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"action": "sign_in"})),
        _step("src", "second"),
    )
    wrong = _make_case("first-wrong", "src", "first", base, {"user": "u", "action": "other"})
    right = _make_case("first-right", "src", "first", base, {"user": "u", "action": "sign_in"})
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})

    assert not _correlation_hit([wrong, second], spec)
    assert _correlation_hit([right, second], spec)


def test_correlation_filter_list_is_in_and_matches_document_lists() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"risk_level": ["medium", "high"]})),
        _step("src", "second"),
    )
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})
    low = _make_case("first-low", "src", "first", base, {"user": "u", "risk_level": "low"})
    high = _make_case("first-high", "src", "first", base, {"user": "u", "risk_level": "high"})
    listed = _make_case(
        "first-listed", "src", "first", base, {"user": "u", "risk_level": ["low", "high"]}
    )

    assert not _correlation_hit([low, second], spec)
    assert _correlation_hit([high, second], spec)
    assert _correlation_hit([listed, second], spec)


def test_correlation_filter_exists_true_and_false() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})
    missing = _make_case("first-missing", "src", "first", base, {"user": "u"})
    present = _make_case(
        "first-present", "src", "first", base, {"user": "u", "forward_to": "x@example.test"}
    )
    require_present = _spec(
        _step("src", "first", filters=_filters({"forward_to": ExistsFilter(True)})),
        _step("src", "second"),
    )
    require_missing = _spec(
        _step("src", "first", filters=_filters({"forward_to": ExistsFilter(False)})),
        _step("src", "second"),
    )

    assert not _correlation_hit([missing, second], require_present)
    assert _correlation_hit([present, second], require_present)
    assert _correlation_hit([missing, second], require_missing)
    assert not _correlation_hit([present, second], require_missing)


def test_correlation_filter_nested_field_and_missing_field() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"resource.type": "ServicePrincipal"})),
        _step("src", "second"),
    )
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})
    nested = _make_case(
        "first-nested",
        "src",
        "first",
        base,
        {"user": "u", "resource": {"type": "ServicePrincipal"}},
    )
    wrong_type = _make_case(
        "first-wrong", "src", "first", base, {"user": "u", "resource": {"type": "User"}}
    )
    missing = _make_case("first-missing", "src", "first", base, {"user": "u"})

    assert _correlation_hit([nested, second], spec)
    assert not _correlation_hit([wrong_type, second], spec)
    assert not _correlation_hit([missing, second], spec)


def test_correlation_filter_all_and_any_of() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step(
            "src",
            "first",
            filters=_filters(
                {"action": "Add-MailboxPermission", "result": "success"},
                any_of=[
                    {"access_rights": "FullAccess"},
                    {"access_rights": ["Owner", "PublishingEditor", "Editor"]},
                ],
            ),
        ),
        _step("src", "second"),
    )
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})
    full_access = _make_case(
        "first-full",
        "src",
        "first",
        base,
        {
            "user": "u",
            "action": "Add-MailboxPermission",
            "result": "success",
            "access_rights": ["FullAccess", "SendAs"],
        },
    )
    editor = _make_case(
        "first-editor",
        "src",
        "first",
        base,
        {
            "user": "u",
            "action": "Add-MailboxPermission",
            "result": "success",
            "access_rights": ["Reviewer", "Editor"],
        },
    )
    wrong_action = _make_case(
        "first-action",
        "src",
        "first",
        base,
        {
            "user": "u",
            "action": "MailItemsAccessed",
            "result": "success",
            "access_rights": ["FullAccess"],
        },
    )
    wrong_rights = _make_case(
        "first-rights",
        "src",
        "first",
        base,
        {
            "user": "u",
            "action": "Add-MailboxPermission",
            "result": "success",
            "access_rights": ["Reviewer"],
        },
    )

    assert _correlation_hit([full_access, second], spec)
    assert _correlation_hit([editor, second], spec)
    assert not _correlation_hit([wrong_action, second], spec)
    assert not _correlation_hit([wrong_rights, second], spec)


def test_correlation_filter_respects_group_by() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"action": "sign_in"})),
        _step("src", "second"),
    )
    first = _make_case("first", "src", "first", base, {"user": "alice", "action": "sign_in"})
    other_user = _make_case(
        "second-other", "src", "second", base + timedelta(seconds=1), {"user": "bob"}
    )
    same_user = _make_case(
        "second-same", "src", "second", base + timedelta(seconds=1), {"user": "alice"}
    )

    assert not _correlation_hit([first, other_user], spec)
    assert _correlation_hit([first, same_user], spec)


def test_correlation_filter_applies_before_match_fields() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first"),
        _step(
            "src",
            "delegation",
            filters=_filters({"action": "Add-MailboxPermission"}),
            match_fields=("mailbox",),
        ),
        _step("src", "access", match_fields=("mailbox",)),
    )
    first = _make_case("first", "src", "first", base, {"user": "u"})
    ignored = _make_case(
        "delegation-ignored",
        "src",
        "delegation",
        base + timedelta(seconds=10),
        {"user": "u", "action": "MailItemsAccessed", "mailbox": "target"},
    )
    allowed_other = _make_case(
        "delegation-allowed",
        "src",
        "delegation",
        base + timedelta(seconds=20),
        {"user": "u", "action": "Add-MailboxPermission", "mailbox": "other"},
    )
    access = _make_case(
        "access",
        "src",
        "access",
        base + timedelta(seconds=30),
        {"user": "u", "mailbox": "target"},
    )

    assert not _correlation_hit([first, ignored, allowed_other, access], spec)

    allowed_target = _make_case(
        "delegation-target",
        "src",
        "delegation",
        base + timedelta(seconds=20),
        {"user": "u", "action": "Add-MailboxPermission", "mailbox": "target"},
    )
    assert _correlation_hit([first, ignored, allowed_target, access], spec)


def test_correlation_backtracks_to_later_matching_candidate() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first"),
        _step("src", "delegation", match_fields=("mailbox",)),
        _step("src", "access", match_fields=("mailbox",)),
    )
    first = _make_case("first", "src", "first", base, {"user": "u"})
    early_other = _make_case(
        "delegation-early",
        "src",
        "delegation",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "other"},
    )
    later_target = _make_case(
        "delegation-later",
        "src",
        "delegation",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target"},
    )
    access = _make_case(
        "access", "src", "access", base + timedelta(seconds=30), {"user": "u", "mailbox": "target"}
    )

    assert _correlation_hit([first, early_other, later_target, access], spec)


@pytest.mark.parametrize(
    ("filter_value", "document_value"),
    [
        (True, 1),
        (True, "true"),
        (1, True),
        ("true", True),
        (False, 0),
        (0, False),
    ],
)
def test_correlation_filter_type_strictness(filter_value: object, document_value: object) -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"flag": filter_value})),
        _step("src", "second"),
    )
    first = _make_case("first", "src", "first", base, {"user": "u", "flag": document_value})
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})

    assert not _correlation_hit([first, second], spec)


def test_correlation_filter_numeric_scalars_match() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first", filters=_filters({"score": 1})),
        _step("src", "second"),
    )
    first = _make_case("first", "src", "first", base, {"user": "u", "score": 1.0})
    second = _make_case("second", "src", "second", base + timedelta(seconds=1), {"user": "u"})

    assert _correlation_hit([first, second], spec)


def test_correlation_window_is_measured_from_the_previous_step() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first"),
        _step("src", "second"),
        _step("src", "third"),
        window_seconds=60,
    )
    first = _make_case("first", "src", "first", base, {"user": "u"})
    second = _make_case("second", "src", "second", base + timedelta(seconds=60), {"user": "u"})
    third = _make_case("third", "src", "third", base + timedelta(seconds=120), {"user": "u"})

    assert _correlation_hit([first, second, third], spec)


def test_correlation_window_rejects_step_beyond_previous_boundary() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first"),
        _step("src", "second"),
        _step("src", "third"),
        window_seconds=60,
    )
    first = _make_case("first", "src", "first", base, {"user": "u"})
    second = _make_case("second", "src", "second", base + timedelta(seconds=60), {"user": "u"})
    third = _make_case("third", "src", "third", base + timedelta(seconds=121), {"user": "u"})

    assert not _correlation_hit([first, second, third], spec)


def test_correlation_exclusion_suppresses_sequence() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox", "scope")),
        _step("src", "delivery", match_fields=("mailbox", "scope")),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox", "scope"),
            exclude=True,
        ),
    )
    denied = _make_case(
        "denied",
        "src",
        "denied",
        base,
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    approved = _make_case(
        "approved",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target", "scope": "dataset", "decision": "approved"},
    )

    assert _correlation_hit([denied, delivery], spec)
    assert not _correlation_hit([denied, delivery, approved], spec)


def test_correlation_exclusion_ignores_earlier_mismatched_and_late_events() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox", "scope")),
        _step("src", "delivery", match_fields=("mailbox", "scope")),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox", "scope"),
            exclude=True,
        ),
    )
    denied = _make_case(
        "denied",
        "src",
        "denied",
        base,
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    earlier = _make_case(
        "earlier",
        "src",
        "approval",
        base - timedelta(seconds=1),
        {"user": "u", "mailbox": "target", "scope": "dataset", "decision": "approved"},
    )
    other_scope = _make_case(
        "other-scope",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target", "scope": "other", "decision": "approved"},
    )
    late = _make_case(
        "late",
        "src",
        "approval",
        base + timedelta(seconds=61),
        {"user": "u", "mailbox": "target", "scope": "dataset", "decision": "approved"},
    )

    assert _correlation_hit([denied, delivery, earlier], spec)
    assert _correlation_hit([denied, delivery, other_scope], spec)
    assert _correlation_hit([denied, delivery, late], spec)


def test_correlation_step_window_overrides_global() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "first"),
        _step("src", "second", window_seconds=120),
        window_seconds=60,
    )
    first = _make_case("first", "src", "first", base, {"user": "u"})
    second = _make_case("second", "src", "second", base + timedelta(seconds=100), {"user": "u"})

    assert _correlation_hit([first, second], spec)


def test_correlation_exclusion_window_overrides_global() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox",)),
        _step("src", "delivery", match_fields=("mailbox",)),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox",),
            exclude=True,
            window_seconds=3600,
        ),
        window_seconds=60,
    )
    denied = _make_case("denied", "src", "denied", base, {"user": "u", "mailbox": "target"})
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target"},
    )
    late_approval = _make_case(
        "approval",
        "src",
        "approval",
        base + timedelta(seconds=600),
        {"user": "u", "mailbox": "target", "decision": "approved"},
    )

    assert not _correlation_hit([denied, delivery, late_approval], spec)


def test_correlation_exclusion_skips_events_missing_declared_fields() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox", "scope")),
        _step("src", "delivery", match_fields=("mailbox", "scope")),
        _step(
            "src",
            "approval",
            match_fields=("mailbox", "scope"),
            exclude=True,
        ),
    )
    denied = _make_case(
        "denied",
        "src",
        "denied",
        base,
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target", "scope": "dataset"},
    )
    missing_scope = _make_case(
        "missing-scope",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target"},
    )
    missing_mailbox = _make_case(
        "missing-mailbox",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "scope": "dataset"},
    )

    assert _correlation_hit([denied, delivery, missing_scope], spec)
    assert _correlation_hit([denied, delivery, missing_mailbox], spec)


def test_correlation_exclusion_skips_events_without_any_values() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_any_fields=("labels",)),
        _step("src", "delivery"),
        _step("src", "approval", match_any_fields=("labels",), exclude=True),
    )
    denied = _make_case(
        "denied",
        "src",
        "denied",
        base,
        {"user": "u", "labels": ["external"]},
    )
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u"},
    )
    missing_labels = _make_case(
        "missing-labels",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u"},
    )

    assert _correlation_hit([denied, delivery, missing_labels], spec)


def test_correlation_exclusion_requires_unexpired_approval() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox",)),
        _step("src", "delivery", match_fields=("mailbox",)),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox",),
            exclude=True,
            valid_until_field="expires_on",
        ),
    )
    denied = _make_case("denied", "src", "denied", base, {"user": "u", "mailbox": "target"})
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target"},
    )
    valid = _make_case(
        "valid",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {
            "user": "u",
            "mailbox": "target",
            "decision": "approved",
            "expires_on": "2026-11-01T01:00:00Z",
        },
    )
    expired = _make_case(
        "expired",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {
            "user": "u",
            "mailbox": "target",
            "decision": "approved",
            "expires_on": "2026-11-01T00:00:05Z",
        },
    )
    missing = _make_case(
        "missing",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target", "decision": "approved"},
    )

    assert not _correlation_hit([denied, delivery, valid], spec)
    assert _correlation_hit([denied, delivery, expired], spec)
    assert _correlation_hit([denied, delivery, missing], spec)


def test_correlation_changed_fields_require_a_different_value() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "interactive", match_fields=("session_id", "src_ip")),
        _step(
            "src",
            "replay",
            match_fields=("session_id",),
            match_changed_fields=("src_ip",),
        ),
    )
    first = _make_case(
        "first",
        "src",
        "interactive",
        base,
        {"user": "u", "session_id": "s1", "src_ip": "203.0.113.10"},
    )
    new_ip = _make_case(
        "new-ip",
        "src",
        "replay",
        base + timedelta(seconds=10),
        {"user": "u", "session_id": "s1", "src_ip": "198.51.100.20"},
    )
    same_ip = _make_case(
        "same-ip",
        "src",
        "replay",
        base + timedelta(seconds=10),
        {"user": "u", "session_id": "s1", "src_ip": "203.0.113.10"},
    )
    missing_ip = _make_case(
        "missing-ip",
        "src",
        "replay",
        base + timedelta(seconds=10),
        {"user": "u", "session_id": "s1"},
    )
    other_session = _make_case(
        "other-session",
        "src",
        "replay",
        base + timedelta(seconds=10),
        {"user": "u", "session_id": "s2", "src_ip": "198.51.100.20"},
    )

    assert _correlation_hit([first, new_ip], spec)
    assert not _correlation_hit([first, same_ip], spec)
    assert not _correlation_hit([first, missing_ip], spec)
    assert not _correlation_hit([first, other_session], spec)


def test_correlation_exclusion_quorum_requires_distinct_approvers() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox",)),
        _step("src", "delivery", match_fields=("mailbox",)),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox",),
            exclude=True,
            min_count=2,
            distinct_by="approver",
        ),
    )
    denied = _make_case("denied", "src", "denied", base, {"user": "u", "mailbox": "target"})
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target"},
    )
    first = _make_case(
        "first",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target", "decision": "approved", "approver": "alice"},
    )
    duplicate = _make_case(
        "duplicate",
        "src",
        "approval",
        base + timedelta(seconds=30),
        {"user": "u", "mailbox": "target", "decision": "approved", "approver": "alice"},
    )
    second = _make_case(
        "second",
        "src",
        "approval",
        base + timedelta(seconds=40),
        {"user": "u", "mailbox": "target", "decision": "approved", "approver": "bob"},
    )
    missing = _make_case(
        "missing",
        "src",
        "approval",
        base + timedelta(seconds=50),
        {"user": "u", "mailbox": "target", "decision": "approved"},
    )

    assert _correlation_hit([denied, delivery, first], spec)
    assert _correlation_hit([denied, delivery, first, duplicate], spec)
    assert _correlation_hit([denied, delivery, first, missing], spec)
    assert not _correlation_hit([denied, delivery, first, second], spec)


def test_correlation_exclusion_rejects_invalid_expiry() -> None:
    base = datetime(2026, 11, 1, tzinfo=UTC)
    spec = _spec(
        _step("src", "denied", match_fields=("mailbox",)),
        _step("src", "delivery", match_fields=("mailbox",)),
        _step(
            "src",
            "approval",
            filters=_filters({"decision": "approved"}),
            match_fields=("mailbox",),
            exclude=True,
            valid_until_field="expires_on",
        ),
    )
    denied = _make_case("denied", "src", "denied", base, {"user": "u", "mailbox": "target"})
    delivery = _make_case(
        "delivery",
        "src",
        "delivery",
        base + timedelta(seconds=10),
        {"user": "u", "mailbox": "target"},
    )
    invalid = _make_case(
        "invalid",
        "src",
        "approval",
        base + timedelta(seconds=20),
        {"user": "u", "mailbox": "target", "decision": "approved", "expires_on": "not-a-time"},
    )

    with pytest.raises(DetectionError, match="invalid expires_on"):
        _correlation_hit([denied, delivery, invalid], spec)


def test_correlation_filters_parse_all_supported_shapes(tmp_path: Path) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(
        path,
        "correlation:\n"
        "  window_seconds: 1800\n"
        "  group_by:\n"
        "    - user\n"
        "  steps:\n"
        "    - source: entra-signin\n"
        "      event_class: sign_in\n"
        "      filters:\n"
        "        all:\n"
        "          result: success\n"
        "          risk_level:\n"
        "            - medium\n"
        "            - high\n"
        "          is_interactive: true\n"
        "          nested.value: 3.5\n"
        "          mixed_values:\n"
        "            - true\n"
        "            - 1\n"
        "            - alpha\n"
        "    - source: entra-audit\n"
        "      event_class: audit\n"
        "      filters:\n"
        "        all:\n"
        "          action: Add owner to service principal\n"
        "        any_of:\n"
        "          - result: success\n"
        "          - forward_to:\n"
        "              exists: false\n"
        "            resource.type: ServicePrincipal\n",
    )
    package = load_detection_package(
        path,
        _sources(),  # type: ignore[arg-type]
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    spec = package.correlation
    assert spec is not None

    first = spec.steps[0].filters.all
    assert first is not None
    conditions = dict(first.conditions)
    assert conditions["result"] == "success"
    assert conditions["risk_level"] == ("medium", "high")
    assert conditions["is_interactive"] is True
    assert conditions["nested.value"] == 3.5
    assert conditions["mixed_values"] == (True, 1, "alpha")

    second = spec.steps[1].filters
    assert second.all is not None
    assert dict(second.all.conditions)["action"] == "Add owner to service principal"
    assert dict(second.any_of[0].conditions) == {"result": "success"}
    nested_group = dict(second.any_of[1].conditions)
    assert nested_group["forward_to"] == ExistsFilter(False)
    assert nested_group["resource.type"] == "ServicePrincipal"


def _filters_correlation(filters_yaml: str) -> str:
    return (
        "correlation:\n"
        "  window_seconds: 1800\n"
        "  group_by:\n"
        "    - user\n"
        "  steps:\n"
        "    - source: entra-signin\n"
        "      event_class: sign_in\n"
        f"{filters_yaml}"
        "    - source: entra-audit\n"
        "      event_class: audit\n"
    )


@pytest.mark.parametrize(
    ("filters_yaml", "message"),
    [
        ("      filters: []\n", "filters must be an object"),
        ("      filters: {}\n", "must declare all or any_of"),
        ("      filters:\n        other: {}\n", "unknown keys"),
        ("      filters:\n        all: {}\n", "must be a non-empty object"),
        ("      filters:\n        any_of: []\n", "any_of must be a non-empty array"),
        (
            "      filters:\n        any_of:\n          - {}\n",
            "any_of entry 1 must be a non-empty object",
        ),
        (
            "      filters:\n        all:\n          'user..name': value\n",
            "dotted path",
        ),
        (
            "      filters:\n        all:\n          'user name': value\n",
            "dotted path",
        ),
        ("      filters:\n        all:\n          user: null\n", "unsupported value type"),
        ("      filters:\n        all:\n          user: []\n", "list must not be empty"),
        (
            "      filters:\n        all:\n          user: [alpha, alpha]\n",
            "must not contain duplicates",
        ),
        (
            "      filters:\n        all:\n          user:\n            exists: 1\n",
            "exists value must be a boolean",
        ),
        (
            "      filters:\n        all:\n          user:\n"
            "            exists: true\n            extra: value\n",
            "object with only an exists boolean",
        ),
        (
            "      filters:\n        all:\n          user:\n"
            "            - alpha\n            - {beta: gamma}\n",
            "list items must be scalars",
        ),
        (
            "      filters:\n        all:\n          user:\n            other: true\n",
            "object with only an exists boolean",
        ),
    ],
)
def test_correlation_filter_validation(tmp_path: Path, filters_yaml: str, message: str) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(path, _filters_correlation(filters_yaml))
    with pytest.raises(DetectionError, match=message):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_correlation_requires_event_class_declared_for_source(tmp_path: Path) -> None:
    path = _copy_correlation(tmp_path)
    _replace_correlation(
        path,
        "correlation:\n"
        "  window_seconds: 1800\n"
        "  group_by:\n"
        "    - user\n"
        "  steps:\n"
        "    - source: entra-signin\n"
        "      event_class: audit\n"
        "    - source: entra-audit\n"
        "      event_class: audit\n",
    )
    with pytest.raises(DetectionError, match="not declared for source"):
        load_detection_package(path, _sources())  # type: ignore[arg-type]


def test_match_values_handles_scalars_lists_and_empty_values() -> None:
    assert _match_values("a") == {"a"}
    assert _match_values(["a", "b"]) == {"a", "b"}
    assert _match_values(None) == set()
    assert _match_values("") == set()
    assert _match_values([]) == set()
    assert _match_values({}) == set()
