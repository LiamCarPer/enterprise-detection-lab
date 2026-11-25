"""Execute detection packages against OpenSearch fixtures."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    scenario: str


FilterScalar = str | int | float | bool


@dataclass(frozen=True)
class ExistsFilter:
    """A filter that only checks whether a field is present."""

    value: bool


FilterValue = FilterScalar | tuple[FilterScalar, ...] | ExistsFilter


@dataclass(frozen=True)
class FilterGroup:
    """A conjunction of field filters."""

    conditions: tuple[tuple[str, FilterValue], ...]


@dataclass(frozen=True)
class StepFilters:
    """Optional step filters: all conditions plus any-of condition groups."""

    all: FilterGroup | None = None
    any_of: tuple[FilterGroup, ...] = ()


@dataclass(frozen=True)
class CorrelationStep:
    source: str
    event_class: str
    match_fields: tuple[str, ...] = ()
    match_any_fields: tuple[str, ...] = ()
    filters: StepFilters = StepFilters()
    exclude: bool = False


@dataclass(frozen=True)
class CorrelationSpec:
    window_seconds: int
    group_by: tuple[str, ...]
    steps: tuple[CorrelationStep, ...]


@dataclass(frozen=True)
class DetectionPackage:
    """A detection and its normalized fixture corpus."""

    detection_id: str
    title: str
    path: Path
    query: dict[str, Any]
    cases: tuple[DetectionCase, ...]
    correlation: CorrelationSpec | None


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
    evaluation_unit: str = "event"

    @property
    def passed(self) -> bool:
        return self.false_negatives == 0 and self.false_positives == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "title": self.title,
            "path": str(self.path),
            "evaluation_unit": self.evaluation_unit,
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


@dataclass(frozen=True)
class BaselineResult:
    """Outcome of executing one detection query against a benign baseline."""

    detection_id: str
    dataset: Path
    sample_size: int
    matched_count: int
    false_positive_rate: float
    latency_ms_p50: float
    latency_ms_p95: float
    matched_ids: tuple[str, ...]
    evaluation_unit: str = "event"

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "dataset": str(self.dataset),
            "sample_size": self.sample_size,
            "evaluation_unit": self.evaluation_unit,
            "matched_count": self.matched_count,
            "false_positive_rate": self.false_positive_rate,
            "latency_ms_p50": self.latency_ms_p50,
            "latency_ms_p95": self.latency_ms_p95,
            "matched_ids": list(self.matched_ids),
        }


def _load_query(
    path: Path,
    meta: Mapping[str, Any],
    override: Path | None = None,
) -> dict[str, Any]:
    if override is None:
        queries = meta.get("queries")
        if not isinstance(queries, Mapping):
            raise DetectionError(f"{path}: meta.queries must be an object")
        reference = queries.get("opensearch")
        if not isinstance(reference, str) or not reference:
            raise DetectionError(f"{path}: meta.queries.opensearch is missing")
        query_path = path / reference
    else:
        query_path = override if override.is_absolute() else path / override

    if not query_path.is_file():
        raise DetectionError(f"{path}: OpenSearch query not found: {query_path}")
    try:
        query = load_json(query_path)
    except ValidationError as exc:
        raise DetectionError(str(exc)) from exc
    if not isinstance(query, Mapping) or "query" not in query:
        raise DetectionError(f"{query_path}: query must be an object with a query field")
    return dict(query)


def _telemetry_event_classes(path: Path, meta: Mapping[str, Any]) -> dict[str, set[str]]:
    telemetry = meta.get("telemetry")
    if not isinstance(telemetry, list) or not telemetry:
        raise DetectionError(f"{path}: meta.telemetry must be a non-empty list")
    event_classes: dict[str, set[str]] = {}
    for item in telemetry:
        if not isinstance(item, Mapping):
            continue
        source = item.get("source")
        if not isinstance(source, str) or not source:
            continue
        declared = event_classes.setdefault(source, set())
        event_class = item.get("event_class")
        if isinstance(event_class, str) and event_class:
            declared.add(event_class)
    if not event_classes:
        raise DetectionError(f"{path}: meta.telemetry has no source")
    return event_classes


def _allowed_sources(path: Path, meta: Mapping[str, Any]) -> set[str]:
    return set(_telemetry_event_classes(path, meta))


def _load_cases(
    path: Path,
    meta: Mapping[str, Any],
    sources: Mapping[str, TelemetrySource],
    *,
    ingest_time: datetime,
) -> tuple[DetectionCase, ...]:
    allowed_sources = _allowed_sources(path, meta)

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
            scenario = fixture.get("scenario")
            if not isinstance(scenario, str) or not scenario:
                scenario = f"{kind}-{position:03d}"
            cases.append(
                DetectionCase(
                    case_id=f"{kind}-{position:03d}",
                    kind=kind,
                    source=source_id,
                    event=normalized,
                    scenario=scenario,
                )
            )

    return tuple(cases)


_FIELD_PATH = re.compile(r"^[^\s.]+(?:\.[^\s.]+)*$")


def _parse_filter_value(
    path: Path,
    position: int,
    field: str,
    value: Any,
) -> FilterValue:
    if isinstance(value, Mapping):
        unknown = set(value) - {"exists"}
        if unknown or "exists" not in value:
            raise DetectionError(
                f"{path}: correlation step {position} filter {field!r} must be a scalar, "
                "a non-empty list of scalars, or an object with only an exists boolean"
            )
        exists = value["exists"]
        if not isinstance(exists, bool):
            raise DetectionError(
                f"{path}: correlation step {position} filter {field!r} exists value "
                "must be a boolean"
            )
        return ExistsFilter(exists)

    if isinstance(value, list):
        if not value:
            raise DetectionError(
                f"{path}: correlation step {position} filter {field!r} list must not be empty"
            )
        normalized: list[FilterScalar] = []
        seen: set[tuple[str, Any]] = set()
        for item in value:
            if isinstance(item, bool):
                key: tuple[str, Any] = ("bool", item)
            elif isinstance(item, (int, float)):
                key = ("number", float(item))
            elif isinstance(item, str):
                key = ("string", item)
            else:
                raise DetectionError(
                    f"{path}: correlation step {position} filter {field!r} list items "
                    "must be scalars"
                )
            if key in seen:
                raise DetectionError(
                    f"{path}: correlation step {position} filter {field!r} list must not "
                    "contain duplicates"
                )
            seen.add(key)
            normalized.append(item)
        return tuple(normalized)

    if isinstance(value, (str, int, float, bool)):
        return value
    raise DetectionError(
        f"{path}: correlation step {position} filter {field!r} has an unsupported value type"
    )


def _parse_filter_group(
    path: Path,
    position: int,
    label: str,
    raw: Any,
) -> FilterGroup:
    if not isinstance(raw, Mapping) or not raw:
        raise DetectionError(
            f"{path}: correlation step {position} filters {label} must be a non-empty object"
        )
    conditions: list[tuple[str, FilterValue]] = []
    for field, value in raw.items():
        if not isinstance(field, str) or not _FIELD_PATH.match(field):
            raise DetectionError(
                f"{path}: correlation step {position} filter field {field!r} must be a "
                "dotted path without empty segments or whitespace"
            )
        conditions.append((field, _parse_filter_value(path, position, field, value)))
    return FilterGroup(tuple(conditions))


def _parse_filters(path: Path, position: int, raw: Any) -> StepFilters:
    if not isinstance(raw, Mapping):
        raise DetectionError(f"{path}: correlation step {position} filters must be an object")
    unknown = set(raw) - {"all", "any_of"}
    if unknown:
        raise DetectionError(
            f"{path}: correlation step {position} filters has unknown keys: {sorted(unknown)}"
        )

    all_group: FilterGroup | None = None
    if "all" in raw:
        all_group = _parse_filter_group(path, position, "all", raw["all"])

    any_groups: tuple[FilterGroup, ...] = ()
    if "any_of" in raw:
        items = raw["any_of"]
        if not isinstance(items, list) or not items:
            raise DetectionError(
                f"{path}: correlation step {position} filters any_of must be a non-empty array"
            )
        any_groups = tuple(
            _parse_filter_group(path, position, f"any_of entry {index}", item)
            for index, item in enumerate(items, start=1)
        )

    if all_group is None and not any_groups:
        raise DetectionError(
            f"{path}: correlation step {position} filters must declare all or any_of"
        )
    return StepFilters(all=all_group, any_of=any_groups)


def _load_correlation(
    path: Path,
    meta: Mapping[str, Any],
    event_classes: Mapping[str, set[str]],
) -> CorrelationSpec | None:
    raw = meta.get("correlation")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise DetectionError(f"{path}: meta.correlation must be an object")

    window = raw.get("window_seconds")
    if not isinstance(window, int) or isinstance(window, bool) or window < 1:
        raise DetectionError(f"{path}: correlation.window_seconds must be a positive integer")

    group_by = raw.get("group_by")
    if (
        not isinstance(group_by, list)
        or not group_by
        or not all(isinstance(item, str) and item for item in group_by)
    ):
        raise DetectionError(f"{path}: correlation.group_by must be a string array")

    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) < 2:
        raise DetectionError(f"{path}: correlation.steps must contain at least two steps")
    steps: list[CorrelationStep] = []
    required_match_fields: set[str] = set()
    required_any_fields: set[str] = set()
    saw_exclude = False
    for position, item in enumerate(raw_steps, start=1):
        if not isinstance(item, Mapping):
            raise DetectionError(f"{path}: correlation step {position} must be an object")
        source = item.get("source")
        event_class = item.get("event_class")
        if not isinstance(source, str) or source not in event_classes:
            raise DetectionError(
                f"{path}: correlation step {position} source {source!r} "
                "is not declared in meta.telemetry"
            )
        if not isinstance(event_class, str) or not event_class:
            raise DetectionError(f"{path}: correlation step {position} event_class is missing")
        if event_class not in event_classes[source]:
            raise DetectionError(
                f"{path}: correlation step {position} event_class {event_class!r} "
                f"is not declared for source {source!r} in meta.telemetry"
            )
        raw_match = item.get("match_fields", [])
        if (
            not isinstance(raw_match, list)
            or not all(isinstance(field, str) and field for field in raw_match)
            or len(set(raw_match)) != len(raw_match)
        ):
            raise DetectionError(
                f"{path}: correlation step {position} match_fields must be a unique string array"
            )
        exclude = item.get("exclude", False)
        if not isinstance(exclude, bool):
            raise DetectionError(f"{path}: correlation step {position} exclude must be a boolean")
        if exclude:
            saw_exclude = True
        elif saw_exclude:
            raise DetectionError(
                f"{path}: correlation non-exclude steps must precede exclude steps"
            )
        raw_match_any = item.get("match_any_fields", [])
        if (
            not isinstance(raw_match_any, list)
            or not all(isinstance(field, str) and field for field in raw_match_any)
            or len(set(raw_match_any)) != len(raw_match_any)
        ):
            raise DetectionError(
                f"{path}: correlation step {position} match_any_fields must be a unique "
                "string array"
            )
        raw_filters = item.get("filters")
        filters = (
            _parse_filters(path, position, raw_filters)
            if raw_filters is not None
            else StepFilters()
        )
        step = CorrelationStep(
            source=source,
            event_class=event_class,
            match_fields=tuple(raw_match),
            match_any_fields=tuple(raw_match_any),
            filters=filters,
            exclude=exclude,
        )
        if not exclude:
            required_match_fields.update(step.match_fields)
            required_any_fields.update(step.match_any_fields)
        steps.append(step)

    if not any(not step.exclude for step in steps):
        raise DetectionError(f"{path}: correlation must contain at least one non-exclude step")
    for position, step in enumerate(steps, start=1):
        if not step.exclude:
            continue
        unknown = set(step.match_fields) - required_match_fields
        if unknown:
            raise DetectionError(
                f"{path}: correlation exclusion step {position} match_fields must be "
                f"established by earlier steps: {', '.join(sorted(unknown))}"
            )
        unknown_any = set(step.match_any_fields) - required_any_fields
        if unknown_any:
            raise DetectionError(
                f"{path}: correlation exclusion step {position} match_any_fields must be "
                f"established by earlier steps: {', '.join(sorted(unknown_any))}"
            )

    return CorrelationSpec(
        window_seconds=window,
        group_by=tuple(group_by),
        steps=tuple(steps),
    )


def _load_baseline_cases(
    package_path: Path,
    dataset_path: Path,
    meta: Mapping[str, Any],
    sources: Mapping[str, TelemetrySource],
    *,
    ingest_time: datetime,
) -> tuple[DetectionCase, ...]:
    allowed_sources = _allowed_sources(package_path, meta)
    if not dataset_path.is_file():
        raise DetectionError(f"Baseline dataset not found: {dataset_path}")
    try:
        fixtures = load_json(dataset_path)
    except ValidationError as exc:
        raise DetectionError(str(exc)) from exc
    if not isinstance(fixtures, list) or not fixtures:
        raise DetectionError(f"{dataset_path}: baseline must be a non-empty array")

    cases: list[DetectionCase] = []
    for position, fixture in enumerate(fixtures, start=1):
        if not isinstance(fixture, Mapping):
            raise DetectionError(f"{dataset_path}: baseline event {position} must be an object")
        if fixture.get("synthetic") is not True:
            raise DetectionError(
                f"{dataset_path}: baseline event {position} must be marked synthetic"
            )
        source_id = fixture.get("source")
        if not isinstance(source_id, str) or source_id not in allowed_sources:
            raise DetectionError(
                f"{dataset_path}: baseline event {position} source {source_id!r} "
                "is not declared in meta.telemetry"
            )
        source = sources.get(source_id)
        if source is None:
            raise DetectionError(f"{dataset_path}: unknown telemetry source {source_id!r}")
        raw_event = fixture.get("event")
        if not isinstance(raw_event, Mapping):
            raise DetectionError(
                f"{dataset_path}: baseline event {position} event must be an object"
            )
        try:
            normalized = normalize_event(source, raw_event, ingest_time=ingest_time)
        except IngestError as exc:
            raise DetectionError(f"{dataset_path}: baseline event {position}: {exc}") from exc
        scenario = fixture.get("scenario")
        if not isinstance(scenario, str) or not scenario:
            scenario = f"baseline-{position:03d}"
        cases.append(
            DetectionCase(
                case_id=f"baseline-{position:03d}",
                kind="benign",
                source=source_id,
                event=normalized,
                scenario=scenario,
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
    event_classes = _telemetry_event_classes(path, meta)
    correlation = _load_correlation(path, meta, event_classes)
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
        correlation=correlation,
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


_MISSING = object()


def _lookup_field(document: Mapping[str, Any], field: str) -> Any:
    current: Any = document
    for part in field.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _lookup_document(document: Mapping[str, Any], field: str) -> Any:
    value = _lookup_field(document, field)
    return None if value is _MISSING else value


def _scalar_equal(expected: FilterScalar, actual: Any) -> bool:
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(expected, bool) and isinstance(actual, bool) and expected == actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return expected == actual
    return type(expected) is type(actual) and expected == actual


def _filter_value_matches(expected: FilterValue, actual: Any) -> bool:
    if isinstance(expected, ExistsFilter):
        present = actual is not _MISSING and actual is not None
        return present == expected.value
    if actual is _MISSING or actual is None:
        return False
    expected_values: tuple[FilterScalar, ...]
    expected_values = expected if isinstance(expected, tuple) else (expected,)
    actual_values = actual if isinstance(actual, (list, tuple)) else (actual,)
    return any(_scalar_equal(item, value) for item in expected_values for value in actual_values)


def _filter_group_matches(document: Mapping[str, Any], group: FilterGroup) -> bool:
    return all(
        _filter_value_matches(expected, _lookup_field(document, field))
        for field, expected in group.conditions
    )


def _filters_match(document: Mapping[str, Any], filters: StepFilters) -> bool:
    if filters.all is not None and not _filter_group_matches(document, filters.all):
        return False
    return not filters.any_of or any(
        _filter_group_matches(document, group) for group in filters.any_of
    )


def _match_values(value: Any) -> set[Any]:
    if isinstance(value, (list, tuple)):
        return {item for item in value if item is not None and item != ""}
    if value is None or value == "" or value == [] or value == {}:
        return set()
    return {value}


def _values_match_targets(
    values: Mapping[str, Any],
    any_values: Mapping[str, set[Any]],
    targets: Mapping[str, Any],
    any_targets: Mapping[str, set[Any]],
) -> bool:
    if any(field in targets and targets[field] != value for field, value in values.items()):
        return False
    return not any(
        field in any_targets and not (any_targets[field] & candidates)
        for field, candidates in any_values.items()
    )


def _excluded(
    ordered: Sequence[Sequence[DetectionCase]],
    spec: CorrelationSpec,
    exclude_indices: Sequence[int],
    anchor_time: datetime | None,
    targets: Mapping[str, Any],
    any_targets: Mapping[str, set[Any]],
) -> bool:
    for step_index in exclude_indices:
        step = spec.steps[step_index]
        for case in ordered[step_index]:
            event_time = case.event.event_time
            if anchor_time is not None and (
                event_time < anchor_time
                or event_time > anchor_time + timedelta(seconds=spec.window_seconds)
            ):
                continue
            values = {
                field: _lookup_document(case.event.document, field) for field in step.match_fields
            }
            if any(value is None or value == "" for value in values.values()):
                continue
            any_values = {
                field: _match_values(_lookup_document(case.event.document, field))
                for field in step.match_any_fields
            }
            if any(not candidates for candidates in any_values.values()):
                continue
            if not _values_match_targets(values, any_values, targets, any_targets):
                continue
            return True
    return False


def _match_steps(
    ordered: Sequence[Sequence[DetectionCase]],
    spec: CorrelationSpec,
) -> bool:
    required_indices = tuple(index for index, step in enumerate(spec.steps) if not step.exclude)
    exclude_indices = tuple(index for index, step in enumerate(spec.steps) if step.exclude)

    def extend(
        position: int,
        current_time: datetime | None,
        anchor_time: datetime | None,
        targets: dict[str, Any],
        any_targets: dict[str, set[Any]],
    ) -> bool:
        if position == len(required_indices):
            return not _excluded(
                ordered,
                spec,
                exclude_indices,
                anchor_time,
                targets,
                any_targets,
            )
        step_index = required_indices[position]
        step = spec.steps[step_index]
        for case in ordered[step_index]:
            event_time = case.event.event_time
            if current_time is not None and (
                event_time < current_time
                or event_time > current_time + timedelta(seconds=spec.window_seconds)
            ):
                continue
            values = {
                field: _lookup_document(case.event.document, field) for field in step.match_fields
            }
            if any(value is None or value == "" for value in values.values()):
                continue
            any_values = {
                field: _match_values(_lookup_document(case.event.document, field))
                for field in step.match_any_fields
            }
            if any(not candidates for candidates in any_values.values()):
                continue
            if not _values_match_targets(values, any_values, targets, any_targets):
                continue
            next_targets = dict(targets)
            next_targets.update(values)
            next_any_targets: dict[str, set[Any]] = {
                field: set(candidates) for field, candidates in any_targets.items()
            }
            for field, candidates in any_values.items():
                next_any_targets[field] = next_any_targets.get(field, set()) | candidates
            next_anchor = anchor_time if anchor_time is not None else event_time
            if extend(position + 1, event_time, next_anchor, next_targets, next_any_targets):
                return True
        return False

    return extend(0, None, None, {}, {})


def _correlation_hit(cases: Sequence[DetectionCase], spec: CorrelationSpec) -> bool:
    grouped: dict[tuple[Any, ...], list[list[DetectionCase]]] = {}
    for step_index, step in enumerate(spec.steps):
        for case in cases:
            if case.source != step.source or case.event.event_class != step.event_class:
                continue
            if not _filters_match(case.event.document, step.filters):
                continue
            key = tuple(_lookup_document(case.event.document, field) for field in spec.group_by)
            if any(value is None or value == "" for value in key):
                continue
            groups = grouped.setdefault(key, [[] for _ in spec.steps])
            groups[step_index].append(case)

    for groups in grouped.values():
        ordered = [sorted(group, key=lambda case: case.event.event_time) for group in groups]
        if _match_steps(ordered, spec):
            return True
    return False


def _score_correlation(
    package: DetectionPackage,
    matched: set[str],
    latencies: Sequence[float],
) -> DetectionResult:
    spec = package.correlation
    assert spec is not None

    scenarios: dict[tuple[str, str], list[DetectionCase]] = {}
    for case in package.cases:
        scenarios.setdefault((case.kind, case.scenario), []).append(case)

    true_positive_ids: list[str] = []
    false_negative_ids: list[str] = []
    false_positive_ids: list[str] = []
    true_negative_ids: list[str] = []
    positive_scenarios = 0
    negative_scenarios = 0
    benign_scenarios = 0

    for (kind, scenario), cases in scenarios.items():
        if kind == "positive":
            positive_scenarios += 1
        elif kind == "negative":
            negative_scenarios += 1
        else:
            benign_scenarios += 1
        matched_cases = [case for case in cases if case.case_id in matched]
        matched_sequence = _correlation_hit(matched_cases, spec)
        if kind == "positive":
            (true_positive_ids if matched_sequence else false_negative_ids).append(scenario)
        else:
            (false_positive_ids if matched_sequence else true_negative_ids).append(scenario)

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
        sample_size=len(scenarios),
        positive_count=positive_scenarios,
        negative_count=negative_scenarios,
        benign_count=benign_scenarios,
        true_positives=true_positives,
        false_negatives=false_negatives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        precision=precision,
        recall=recall,
        false_positive_rate=false_positive_rate,
        latency_ms_p50=_percentile(latencies, 0.50),
        latency_ms_p95=_percentile(latencies, 0.95),
        matched_ids=tuple(sorted(true_positive_ids + false_positive_ids)),
        missed_ids=tuple(sorted(false_negative_ids)),
        false_positive_ids=tuple(sorted(false_positive_ids)),
        evaluation_unit="scenario",
    )


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
    if result.evaluation_unit == "scenario":
        method = (
            "Synthetic sequence replay against OpenSearch; native query plus "
            "correlation evaluation."
        )
        limitations = [
            f"Curated synthetic scenarios; sample size {result.sample_size}.",
            "Correlation metrics are scenario-level; each fixture scenario is one evaluation case.",
            "Window and grouping are evaluated by the runner; production scheduling is out of "
            "scope.",
            "Sigma rule is not executed; the native OpenSearch query is the tested path.",
        ]
    else:
        method = "Synthetic fixture replay against OpenSearch; native query only."
        limitations = [
            f"Curated synthetic fixtures; sample size {result.sample_size}.",
            "Local OpenSearch latency; not representative of production.",
            "Sigma rule is not executed; the native OpenSearch query is the tested path.",
        ]

    metrics = {
        "detection_id": result.detection_id,
        "measured_at": format_timestamp(datetime.now(UTC)),
        "sample_size": result.sample_size,
        "evaluation_unit": result.evaluation_unit,
        "precision": round(result.precision, 6),
        "recall": round(result.recall, 6),
        "false_positive_rate": round(result.false_positive_rate, 6),
        "latency_ms_p50": round(result.latency_ms_p50, 3),
        "latency_ms_p95": round(result.latency_ms_p95, 3),
        "method": method,
        "limitations": limitations,
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
        result = (
            _score_correlation(package, matched, latencies)
            if package.correlation is not None
            else _score(package, matched, latencies)
        )
        if write_metrics and result.passed:
            write_detection_metrics(package, result)
        return result
    finally:
        active.delete_matching(index)
        if client is None:
            active.close()


def run_baseline(
    detection_id: str,
    dataset: Path,
    *,
    root: Path = config.ROOT,
    sources: Mapping[str, TelemetrySource] | None = None,
    client: OpenSearchClient | None = None,
    query_path: Path | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = "edl-events-baseline",
    latency_runs: int = 3,
) -> BaselineResult:
    """Execute one detection query against a benign baseline dataset."""
    if latency_runs < 1:
        raise DetectionError("latency_runs must be at least 1")
    if sources is None:
        try:
            sources = {source.id: source for source in load_sources(root)}
        except ValidationError as exc:
            raise DetectionError(str(exc)) from exc

    selected = _select_detections(root, detection_id, include_templates=True)
    if not selected:
        raise DetectionError(f"Detection not found: {detection_id}")
    if len(selected) > 1:
        raise DetectionError(f"Multiple detections found for ID: {detection_id}")
    package_path = selected[0].path
    meta = load_mapping(package_path / "meta.yaml")
    event_classes = _telemetry_event_classes(package_path, meta)
    correlation = _load_correlation(package_path, meta, event_classes)

    query = _load_query(package_path, meta, query_path)
    dataset_path = dataset if dataset.is_absolute() else root / dataset
    cases = _load_baseline_cases(
        package_path,
        dataset_path,
        meta,
        sources,
        ingest_time=ingest_time or datetime.now(UTC),
    )
    case_ids = {case.case_id for case in cases}

    active = client or OpenSearchClient()
    index = f"{index_prefix}-{detection_id.lower()}-{uuid4().hex[:8]}"
    try:
        active.bulk(
            index,
            [(case.case_id, case.event.document) for case in cases],
            refresh=True,
        )
        body = build_search_body(query, len(cases))
        latencies: list[float] = []
        response: dict[str, Any] = {}
        for _ in range(latency_runs):
            started = time.perf_counter()
            response = active.search(index, body)
            latencies.append((time.perf_counter() - started) * 1000.0)

        matched = extract_hit_ids(response) & case_ids
        if correlation is not None:
            scenarios: dict[str, list[DetectionCase]] = {}
            for case in cases:
                scenarios.setdefault(case.scenario, []).append(case)
            matched_scenarios = [
                scenario
                for scenario, scenario_cases in scenarios.items()
                if _correlation_hit(
                    [case for case in scenario_cases if case.case_id in matched],
                    correlation,
                )
            ]
            return BaselineResult(
                detection_id=detection_id,
                dataset=dataset_path,
                sample_size=len(scenarios),
                matched_count=len(matched_scenarios),
                false_positive_rate=len(matched_scenarios) / len(scenarios),
                latency_ms_p50=_percentile(latencies, 0.50),
                latency_ms_p95=_percentile(latencies, 0.95),
                matched_ids=tuple(sorted(matched_scenarios)),
                evaluation_unit="scenario",
            )

        return BaselineResult(
            detection_id=detection_id,
            dataset=dataset_path,
            sample_size=len(cases),
            matched_count=len(matched),
            false_positive_rate=len(matched) / len(cases),
            latency_ms_p50=_percentile(latencies, 0.50),
            latency_ms_p95=_percentile(latencies, 0.95),
            matched_ids=tuple(sorted(matched)),
        )
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
