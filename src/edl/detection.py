"""Execute detection packages against OpenSearch fixtures."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from . import config
from .artifacts import ArtifactRef, discover_artifacts
from .errors import DetectionError, IngestError, ValidationError
from .ingest import CanonicalEvent, OpenSearchClient, format_timestamp, normalize_event
from .loader import load_json, load_mapping
from .telemetry import TelemetrySource, load_sources

FixtureKind = Literal["positive", "negative", "benign"]
FIXTURE_KINDS: tuple[FixtureKind, ...] = ("positive", "negative", "benign")


@dataclass(frozen=True)
class DetectionCase:
    """One normalized fixture event."""

    case_id: str
    kind: FixtureKind
    source: str
    event: CanonicalEvent


@dataclass(frozen=True)
class DetectionPackage:
    """A detection and its normalized fixture corpus."""

    detection_id: str
    title: str
    path: Path
    query: dict[str, Any]
    cases: tuple[DetectionCase, ...]


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of executing one detection against its fixtures."""

    detection_id: str
    title: str
    path: Path
    sample_size: int
    positive_count: int
    negative_count: int
    benign_count: int
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    latency_ms_p50: float
    latency_ms_p95: float
    matched_ids: tuple[str, ...]
    missed_ids: tuple[str, ...]
    false_positive_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.false_negatives == 0 and self.false_positives == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "title": self.title,
            "path": str(self.path),
            "sample_size": self.sample_size,
            "fixtures": {
                "positive": self.positive_count,
                "negative": self.negative_count,
                "benign": self.benign_count,
            },
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "latency_ms_p50": self.latency_ms_p50,
            "latency_ms_p95": self.latency_ms_p95,
            "matched_ids": list(self.matched_ids),
            "missed_ids": list(self.missed_ids),
            "false_positive_ids": list(self.false_positive_ids),
            "passed": self.passed,
        }


def _load_query(path: Path, meta: Mapping[str, Any]) -> dict[str, Any]:
    queries = meta.get("queries")
    if not isinstance(queries, Mapping):
        raise DetectionError(f"{path}: meta.queries must be an object")
    reference = queries.get("opensearch")
    if not isinstance(reference, str) or not reference:
        raise DetectionError(f"{path}: meta.queries.opensearch is missing")

    query_path = path / reference
    if not query_path.is_file():
        raise DetectionError(f"{path}: OpenSearch query not found: {query_path}")
    try:
        query = load_json(query_path)
    except ValidationError as exc:
        raise DetectionError(str(exc)) from exc
    if not isinstance(query, Mapping) or "query" not in query:
        raise DetectionError(f"{query_path}: query must be an object with a query field")
    return dict(query)


def _load_cases(
    path: Path,
    meta: Mapping[str, Any],
    sources: Mapping[str, TelemetrySource],
    *,
    ingest_time: datetime,
) -> tuple[DetectionCase, ...]:
    telemetry = meta.get("telemetry")
    if not isinstance(telemetry, list) or not telemetry:
        raise DetectionError(f"{path}: meta.telemetry must be a non-empty list")
    allowed_sources: set[str] = set()
    for item in telemetry:
        if isinstance(item, Mapping) and isinstance(item.get("source"), str):
            allowed_sources.add(str(item["source"]))
    if not allowed_sources:
        raise DetectionError(f"{path}: meta.telemetry has no source")

    cases: list[DetectionCase] = []
    for kind in FIXTURE_KINDS:
        fixture_path = path / "fixtures" / f"{kind}.json"
        if not fixture_path.is_file():
            raise DetectionError(f"{path}: fixture not found: {fixture_path}")
        try:
            fixtures = load_json(fixture_path)
        except ValidationError as exc:
            raise DetectionError(str(exc)) from exc
        if not isinstance(fixtures, list) or not fixtures:
            raise DetectionError(f"{fixture_path}: fixture must be a non-empty array")

        for position, fixture in enumerate(fixtures, start=1):
            if not isinstance(fixture, Mapping):
                raise DetectionError(f"{fixture_path}: fixture {position} must be an object")
            if fixture.get("synthetic") is not True:
                raise DetectionError(f"{fixture_path}: fixture {position} must be marked synthetic")
            source_id = fixture.get("source")
            if not isinstance(source_id, str) or source_id not in allowed_sources:
                raise DetectionError(
                    f"{fixture_path}: fixture {position} source {source_id!r} "
                    "is not declared in meta.telemetry"
                )
            source = sources.get(source_id)
            if source is None:
                raise DetectionError(f"{fixture_path}: unknown telemetry source {source_id!r}")
            raw_event = fixture.get("event")
            if not isinstance(raw_event, Mapping):
                raise DetectionError(f"{fixture_path}: fixture {position} event must be an object")
            try:
                normalized = normalize_event(source, raw_event, ingest_time=ingest_time)
            except IngestError as exc:
                raise DetectionError(f"{fixture_path}: fixture {position}: {exc}") from exc
            cases.append(
                DetectionCase(
                    case_id=f"{kind}-{position:03d}",
                    kind=kind,
                    source=source_id,
                    event=normalized,
                )
            )

    return tuple(cases)


def load_detection_package(
    path: Path,
    sources: Mapping[str, TelemetrySource],
    *,
    ingest_time: datetime | None = None,
) -> DetectionPackage:
    """Load and normalize a detection package for execution."""
    try:
        meta = load_mapping(path / "meta.yaml")
    except ValidationError as exc:
        raise DetectionError(str(exc)) from exc

    detection_id = meta.get("id")
    title = meta.get("title")
    if not isinstance(detection_id, str) or not detection_id:
        raise DetectionError(f"{path}: meta.id is missing")
    if not isinstance(title, str) or not title:
        raise DetectionError(f"{path}: meta.title is missing")

    query = _load_query(path, meta)
    cases = _load_cases(
        path,
        meta,
        sources,
        ingest_time=ingest_time or datetime.now(UTC),
    )
    return DetectionPackage(
        detection_id=detection_id,
        title=title,
        path=path,
        query=query,
        cases=cases,
    )


def build_search_body(query: Mapping[str, Any], size: int) -> dict[str, Any]:
    """Ensure the query returns every fixture hit."""
    body = dict(query)
    requested = body.get("size")
    existing = requested if isinstance(requested, int) and not isinstance(requested, bool) else 0
    body["size"] = max(existing, size)
    body["track_total_hits"] = True
    return body


def extract_hit_ids(response: Mapping[str, Any]) -> set[str]:
    """Return all document IDs from an OpenSearch search response."""
    hits = response.get("hits")
    if not isinstance(hits, Mapping):
        raise DetectionError("OpenSearch search response has no hits object")
    items = hits.get("hits")
    if not isinstance(items, list):
        raise DetectionError("OpenSearch search response has no hits array")
    matched: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        doc_id = item.get("_id")
        if isinstance(doc_id, str):
            matched.add(doc_id)
    return matched


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        raise DetectionError("Cannot calculate a percentile from no samples")
    ordered = sorted(values)
    position = round((len(ordered) - 1) * fraction)
    return ordered[max(0, min(position, len(ordered) - 1))]


def _score(
    package: DetectionPackage,
    matched: set[str],
    latencies: Sequence[float],
) -> DetectionResult:
    positive_ids = {case.case_id for case in package.cases if case.kind == "positive"}
    other_ids = {case.case_id for case in package.cases if case.kind != "positive"}
    true_positive_ids = positive_ids & matched
    false_negative_ids = positive_ids - matched
    false_positive_ids = other_ids & matched
    true_negative_ids = other_ids - matched

    true_positives = len(true_positive_ids)
    false_negatives = len(false_negative_ids)
    false_positives = len(false_positive_ids)
    true_negatives = len(true_negative_ids)

    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 0.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 0.0
    )
    false_positive_rate = (
        false_positives / (false_positives + true_negatives)
        if false_positives + true_negatives
        else 0.0
    )

    return DetectionResult(
        detection_id=package.detection_id,
        title=package.title,
        path=package.path,
        sample_size=len(package.cases),
        positive_count=len(positive_ids),
        negative_count=sum(case.kind == "negative" for case in package.cases),
        benign_count=sum(case.kind == "benign" for case in package.cases),
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        precision=precision,
        recall=recall,
        false_positive_rate=false_positive_rate,
        latency_ms_p50=_percentile(latencies, 0.50),
        latency_ms_p95=_percentile(latencies, 0.95),
        matched_ids=tuple(sorted(matched)),
        missed_ids=tuple(sorted(false_negative_ids)),
        false_positive_ids=tuple(sorted(false_positive_ids)),
    )


def write_detection_metrics(package: DetectionPackage, result: DetectionResult) -> Path:
    """Write schema-compatible metrics for a passing detection."""
    metrics = {
        "detection_id": result.detection_id,
        "measured_at": format_timestamp(datetime.now(UTC)),
        "sample_size": result.sample_size,
        "precision": round(result.precision, 6),
        "recall": round(result.recall, 6),
        "false_positive_rate": round(result.false_positive_rate, 6),
        "latency_ms_p50": round(result.latency_ms_p50, 3),
        "latency_ms_p95": round(result.latency_ms_p95, 3),
        "method": "Synthetic fixture replay against OpenSearch; native query only.",
        "limitations": [
            f"Curated synthetic fixtures; sample size {result.sample_size}.",
            "Local OpenSearch latency; not representative of production.",
            "Sigma rule is not executed; the native OpenSearch query is the tested path.",
        ],
    }
    path = package.path / "metrics.json"
    path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return path


def run_detection(
    path: Path,
    *,
    root: Path = config.ROOT,
    sources: Mapping[str, TelemetrySource] | None = None,
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = "edl-events-detect",
    latency_runs: int = 5,
    write_metrics: bool = False,
) -> DetectionResult:
    """Execute one detection against its fixtures in a temporary index."""
    if latency_runs < 1:
        raise DetectionError("latency_runs must be at least 1")
    if sources is None:
        try:
            sources = {source.id: source for source in load_sources(root)}
        except ValidationError as exc:
            raise DetectionError(str(exc)) from exc

    package = load_detection_package(path, sources, ingest_time=ingest_time)
    active = client or OpenSearchClient()
    index = f"{index_prefix}-{package.detection_id.lower()}-{uuid4().hex[:8]}"
    try:
        active.bulk(
            index,
            [(case.case_id, case.event.document) for case in package.cases],
            refresh=True,
        )
        body = build_search_body(package.query, len(package.cases))
        latencies: list[float] = []
        response: dict[str, Any] = {}
        for _ in range(latency_runs):
            started = time.perf_counter()
            response = active.search(index, body)
            latencies.append((time.perf_counter() - started) * 1000.0)

        matched = extract_hit_ids(response)
        result = _score(package, matched, latencies)
        if write_metrics and result.passed:
            write_detection_metrics(package, result)
        return result
    finally:
        active.delete_matching(index)
        if client is None:
            active.close()


def _select_detections(
    root: Path,
    detection_id: str | None,
    *,
    include_templates: bool,
) -> list[ArtifactRef]:
    selected: list[ArtifactRef] = []
    for ref in discover_artifacts(root):
        if ref.kind != "detection":
            continue
        try:
            meta = load_mapping(ref.meta_path)
        except ValidationError as exc:
            raise DetectionError(str(exc)) from exc
        candidate_id = meta.get("id")
        is_template = "_template" in ref.path.parts
        if detection_id is not None:
            if candidate_id == detection_id:
                selected.append(ref)
        elif include_templates or not is_template:
            selected.append(ref)
    return selected


def run_detections(
    root: Path = config.ROOT,
    *,
    detection_id: str | None = None,
    include_templates: bool = False,
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = "edl-events-detect",
    latency_runs: int = 5,
    write_metrics: bool = False,
) -> list[DetectionResult]:
    """Execute all selected detections, skipping templates by default."""
    try:
        sources = {source.id: source for source in load_sources(root)}
    except ValidationError as exc:
        raise DetectionError(str(exc)) from exc

    selected = _select_detections(root, detection_id, include_templates=include_templates)
    if detection_id is not None and not selected:
        raise DetectionError(f"Detection not found: {detection_id}")
    if not selected:
        raise DetectionError("No detections found")

    active = client or OpenSearchClient()
    try:
        return [
            run_detection(
                ref.path,
                root=root,
                sources=sources,
                client=active,
                ingest_time=ingest_time,
                index_prefix=index_prefix,
                latency_runs=latency_runs,
                write_metrics=write_metrics,
            )
            for ref in selected
        ]
    finally:
        if client is None:
            active.close()
