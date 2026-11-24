"""Artifact, telemetry, and repository validation."""

from __future__ import annotations

import shutil
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from . import config
from .artifacts import (
    ArtifactRef,
    discover_artifacts,
    expected_domain_from_id,
    relative_path,
)
from .errors import ValidationError
from .loader import load_json, load_mapping
from .models import ArtifactResult, Issue, Severity, ValidationReport
from .telemetry import (
    TelemetrySource,
    discover_telemetry_sources,
    load_telemetry_source,
    source_path,
    validate_source_shape,
)


def _issue(
    result: ArtifactResult,
    code: str,
    message: str,
    severity: Severity = "error",
) -> None:
    result.issues.append(
        Issue(
            code=code,
            message=message,
            severity=severity,
            artifact_type=result.artifact_type,
            artifact_id=result.artifact_id,
            path=result.path,
        )
    )


def _global_issue(
    report: ValidationReport,
    code: str,
    message: str,
    severity: Severity = "error",
) -> None:
    report.global_issues.append(
        Issue(
            code=code,
            message=message,
            severity=severity,
            artifact_type="repository",
            artifact_id="repository",
            path=".",
        )
    )


def _schema_validate(
    data: Any,
    schema_name: str,
    result: ArtifactResult,
) -> None:
    schema_path = config.SCHEMAS_DIR / schema_name
    if not schema_path.exists():
        _issue(result, "schema.missing", f"Schema not found: {schema_path}")
        return
    try:
        schema = load_json(schema_path)
    except ValidationError as exc:
        _issue(result, "schema.invalid", str(exc))
        return

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(data),
        key=lambda error: tuple(str(part) for part in error.path),
    )
    for error in errors:
        location = "/".join(str(part) for part in error.path) or "$"
        _issue(result, "schema", f"{location}: {error.message}")


def _require(
    artifact_dir: Path,
    result: ArtifactResult,
    relative: str,
    code: str,
    severity: Severity = "error",
) -> None:
    if not (artifact_dir / relative).exists():
        _issue(result, code, f"Missing required file: {relative}", severity)


def _load_meta(
    ref: ArtifactRef,
    result: ArtifactResult,
) -> dict[str, Any] | None:
    try:
        data = load_mapping(ref.meta_path)
    except ValidationError as exc:
        _issue(result, "meta", str(exc))
        return None

    result.artifact_id = str(data.get("id", result.artifact_id))
    result.status = str(data.get("status", "unknown"))
    return data


def _safe_relative(value: str) -> bool:
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def _validate_detection(
    ref: ArtifactRef,
    root: Path,
    result: ArtifactResult,
    check_sigma: bool,
) -> dict[str, Any] | None:
    meta = _load_meta(ref, result)
    if meta is None:
        return None

    _schema_validate(meta, "detection.schema.json", result)

    detection_id = str(meta.get("id", ""))
    expected_domain = expected_domain_from_id(detection_id)
    if expected_domain is None:
        _issue(result, "id", f"Invalid detection ID: {detection_id!r}")
    else:
        if meta.get("domain") != expected_domain:
            _issue(
                result,
                "domain",
                f"Domain {meta.get('domain')!r} does not match ID {detection_id!r} "
                f"({expected_domain})",
            )
        relative = ref.path.relative_to(root / "detections")
        path_domain = relative.parts[0] if relative.parts else ""
        if path_domain != expected_domain:
            _issue(
                result,
                "path.domain",
                f"Path domain {path_domain!r} does not match ID {detection_id!r} "
                f"({expected_domain})",
            )

    _require(ref.path, result, "rule.sigma.yml", "file.rule")
    _require(ref.path, result, "runbook.md", "file.runbook")
    _require(ref.path, result, "metrics.json", "file.metrics")
    _require(ref.path, result, "notes.md", "file.notes")

    query_dir = ref.path / "queries"
    if not query_dir.is_dir():
        _issue(result, "file.queries", "Missing queries/ directory")
    elif not any(path.is_file() for path in query_dir.iterdir()):
        _issue(result, "file.queries", "queries/ directory is empty")

    queries = meta.get("queries")
    if isinstance(queries, dict):
        for backend, value in queries.items():
            if not isinstance(value, str):
                _issue(result, "query.path", f"Query {backend} is not a path string")
                continue
            if not _safe_relative(value):
                _issue(result, "query.path", f"Query {backend} path is not safe: {value}")
                continue
            if not (ref.path / value).exists():
                _issue(result, "query.missing", f"Query {backend} file not found: {value}")

    for kind in ("positive", "negative", "benign"):
        fixture_path = ref.path / "fixtures" / f"{kind}.json"
        if not fixture_path.exists():
            _issue(result, "fixture.missing", f"Missing fixture: fixtures/{kind}.json")
            continue
        try:
            fixture_data = load_json(fixture_path)
        except ValidationError as exc:
            _issue(result, "fixture.invalid", str(exc))
            continue
        if not isinstance(fixture_data, list):
            _issue(result, "fixture.shape", f"fixtures/{kind}.json must be a JSON array")
            continue
        _schema_validate(fixture_data, "fixture.schema.json", result)
        tests = meta.get("tests")
        if isinstance(tests, dict):
            expected = tests.get(kind)
            if isinstance(expected, int) and expected != len(fixture_data):
                _issue(
                    result,
                    "fixture.count",
                    f"fixtures/{kind}.json has {len(fixture_data)} event(s), "
                    f"meta.tests.{kind} says {expected}",
                )

    tests_dir = ref.path / "tests"
    if not tests_dir.is_dir() or not any(tests_dir.glob("test_*.py")):
        _issue(result, "file.tests", "Missing tests/test_*.py")

    metrics_path = ref.path / "metrics.json"
    if metrics_path.exists():
        try:
            metrics_data = load_json(metrics_path)
        except ValidationError as exc:
            _issue(result, "metrics.invalid", str(exc))
        else:
            if isinstance(metrics_data, dict):
                _schema_validate(metrics_data, "metrics.schema.json", result)
                metric_id = metrics_data.get("detection_id")
                if metric_id != detection_id:
                    _issue(
                        result,
                        "metrics.id",
                        f"metrics.json detection_id {metric_id!r} does not match {detection_id!r}",
                    )

    runbook = meta.get("runbook")
    if isinstance(runbook, str):
        if not _safe_relative(runbook):
            _issue(result, "runbook.path", f"Runbook path is not safe: {runbook}")
        elif not (ref.path / runbook).exists():
            _issue(result, "runbook.missing", f"Runbook not found: {runbook}")

    if meta.get("status") == "production":
        if not metrics_path.exists():
            _issue(result, "status.metrics", "production detections require metrics.json")
        if not (ref.path / "notes.md").exists():
            _issue(result, "status.notes", "production detections require notes.md")

    if check_sigma:
        _validate_sigma(ref, result)

    return meta


def _validate_sigma(ref: ArtifactRef, result: ArtifactResult) -> None:
    sigma = shutil.which("sigma")
    if sigma is None:
        _issue(
            result,
            "sigma.missing",
            "sigma CLI not found; install sigma-cli or omit --sigma",
        )
        return
    process = subprocess.run(
        [sigma, "check", str(ref.path / "rule.sigma.yml")],
        cwd=str(ref.path),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip() or "sigma check failed"
        _issue(result, "sigma", detail[:500])


def _validate_investigation(
    ref: ArtifactRef,
    result: ArtifactResult,
    detection_ids: set[str],
) -> dict[str, Any] | None:
    meta = _load_meta(ref, result)
    if meta is None:
        return None

    _schema_validate(meta, "investigation.schema.json", result)

    for relative in (
        "README.md",
        "timeline.md",
        "response.md",
        "lessons.md",
        "executive-summary.md",
    ):
        _require(ref.path, result, relative, f"file.{relative.split('.')[0]}")

    query_dir = ref.path / "queries"
    if not query_dir.is_dir() or not any(path.is_file() for path in query_dir.iterdir()):
        _issue(result, "file.queries", "queries/ directory is missing or empty")

    evidence_dir = ref.path / "evidence"
    if not evidence_dir.is_dir() or not any(path.is_file() for path in evidence_dir.iterdir()):
        _issue(result, "file.evidence", "evidence/ directory is missing or empty")

    detections = meta.get("detections")
    if isinstance(detections, list):
        for detection_id in detections:
            if isinstance(detection_id, str) and detection_id not in detection_ids:
                _issue(result, "detection.link", f"Unknown detection ID: {detection_id}")

    evidence_ids: set[str] = set()
    evidence = meta.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, dict):
                continue
            evidence_id = item.get("id")
            if isinstance(evidence_id, str):
                evidence_ids.add(evidence_id)
            path_value = item.get("path")
            if isinstance(path_value, str):
                if not _safe_relative(path_value):
                    _issue(result, "evidence.path", f"Evidence path is not safe: {path_value}")
                elif not (ref.path / path_value).exists():
                    _issue(result, "evidence.missing", f"Evidence file not found: {path_value}")

    timeline = meta.get("timeline")
    if isinstance(timeline, list):
        for item in timeline:
            if not isinstance(item, dict):
                continue
            evidence_id = item.get("evidence_id")
            if isinstance(evidence_id, str) and evidence_id not in evidence_ids:
                _issue(
                    result,
                    "timeline.evidence",
                    f"Timeline references unknown evidence: {evidence_id}",
                )

    return meta


def _validate_telemetry_source(
    source: TelemetrySource,
    root: Path,
    result: ArtifactResult,
) -> None:
    _schema_validate(source.data, "telemetry-source.schema.json", result)
    for error in validate_source_shape(source):
        _issue(result, "telemetry.source", error)

    sample = source.data.get("sample_data")
    if isinstance(sample, dict):
        sample_path = source_path(root, source)
        if not sample_path.exists():
            _issue(
                result,
                "telemetry.sample",
                f"Sample data path not found: {sample.get('path')}",
            )


def _mark_duplicates(results: list[ArtifactResult], report: ValidationReport) -> None:
    by_id: dict[str, list[ArtifactResult]] = {}
    for result in results:
        if result.artifact_id:
            by_id.setdefault(result.artifact_id, []).append(result)

    for artifact_id, duplicates in by_id.items():
        if len(duplicates) < 2:
            continue
        for duplicate in duplicates:
            _issue(
                duplicate,
                "duplicate.id",
                f"Duplicate artifact ID: {artifact_id}",
            )
        _global_issue(
            report,
            "duplicate.id",
            f"Duplicate artifact ID across artifacts: {artifact_id}",
        )


def _validate_exceptions(
    root: Path,
    detection_ids: set[str],
    report: ValidationReport,
) -> None:
    path = root / "detections" / "exceptions.yaml"
    if not path.exists():
        return
    try:
        data = load_mapping(path)
    except ValidationError as exc:
        _global_issue(report, "exception.load", str(exc))
        return

    catalog = ArtifactResult(
        artifact_type="exception-catalog",
        artifact_id="detections/exceptions.yaml",
        path=relative_path(path, root),
        status="tested",
    )
    _schema_validate(data, "exceptions.schema.json", catalog)
    report.global_issues.extend(catalog.issues)

    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list):
        return

    seen: set[str] = set()
    for exception in exceptions:
        if not isinstance(exception, dict):
            continue
        exception_id = str(exception.get("id", ""))
        detection_id = str(exception.get("detection_id", ""))
        if exception_id in seen:
            _global_issue(
                report,
                "exception.duplicate",
                f"Duplicate exception ID: {exception_id}",
            )
        seen.add(exception_id)

        if detection_id not in detection_ids:
            _global_issue(
                report,
                "exception.detection",
                f"Exception {exception_id} references unknown detection {detection_id}",
            )

        expires = exception.get("expires")
        if isinstance(expires, str):
            try:
                if date.fromisoformat(expires) < date.today():
                    _global_issue(
                        report,
                        "exception.expired",
                        f"Exception {exception_id} expired on {expires}",
                        severity="warning",
                    )
            except ValueError:
                pass


def validate_repository(
    root: Path = config.ROOT,
    include_path: Path | None = None,
    *,
    check_sigma: bool = False,
    strict: bool = False,
) -> ValidationReport:
    """Validate all artifacts and telemetry sources under root."""
    root = root.resolve()
    if include_path is not None:
        include_path = include_path.resolve()
        if include_path.is_file():
            include_path = include_path.parent

    all_refs = discover_artifacts(root, None)
    detection_ids: set[str] = set()
    for ref in all_refs:
        if ref.kind != "detection":
            continue
        try:
            meta = load_mapping(ref.meta_path)
        except ValidationError:
            continue
        detection_id = meta.get("id")
        if isinstance(detection_id, str):
            detection_ids.add(detection_id)

    refs = discover_artifacts(root, include_path)
    detection_refs = [ref for ref in refs if ref.kind == "detection"]
    investigation_refs = [ref for ref in refs if ref.kind == "investigation"]

    report = ValidationReport()
    detection_results: list[ArtifactResult] = []

    for ref in detection_refs:
        result = ArtifactResult(
            artifact_type="detection",
            artifact_id=ref.path.name,
            path=relative_path(ref.path, root),
            status="unknown",
        )
        _validate_detection(ref, root, result, check_sigma)
        detection_results.append(result)

    investigation_results: list[ArtifactResult] = []
    for ref in investigation_refs:
        result = ArtifactResult(
            artifact_type="investigation",
            artifact_id=ref.path.name,
            path=relative_path(ref.path, root),
            status="unknown",
        )
        _validate_investigation(ref, result, detection_ids)
        investigation_results.append(result)

    source_results: list[ArtifactResult] = []
    source_paths = discover_telemetry_sources(root)
    if include_path is not None:
        source_paths = [
            path
            for path in source_paths
            if path.is_relative_to(include_path) or include_path.is_relative_to(path)
        ]

    loaded_sources: list[TelemetrySource] = []
    for path in source_paths:
        result = ArtifactResult(
            artifact_type="telemetry-source",
            artifact_id=path.stem,
            path=relative_path(path, root),
            status="unknown",
        )
        try:
            source = load_telemetry_source(path)
            loaded_sources.append(source)
            result.artifact_id = source.id or result.artifact_id
            result.status = source.status
            _validate_telemetry_source(source, root, result)
        except ValidationError as exc:
            _issue(result, "telemetry.load", str(exc))
        source_results.append(result)

    _validate_exceptions(root, detection_ids, report)

    report.artifacts = detection_results + investigation_results + source_results
    _mark_duplicates(report.artifacts, report)
    report.recompute_summary()

    if strict:
        report.promote_warnings()

    return report
