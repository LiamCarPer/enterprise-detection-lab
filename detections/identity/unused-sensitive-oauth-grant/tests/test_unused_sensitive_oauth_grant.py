from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 5, "negative": 6, "benign": 9}
EXPECTED_SCENARIO_COUNTS = {"positive": 3, "negative": 3, "benign": 6}


def test_query_uses_sensitive_grant_and_app_activity_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-audit" in query
    assert "m365-audit" in query
    assert '"approved_app": false' in query
    assert '"sensitive_scope": true' in query
    assert '"offline_access": true' in query
    assert '"app_access": true' in query


def test_correlation_metadata_uses_a_thirty_day_exclusion_window() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-012" in meta
    assert "window_seconds: 2592000" in meta
    assert "group_by:\n    - app_identity" in meta
    assert meta.count("exclude: true") == 3
    assert "event_class: mail_access" in meta
    assert "event_class: sharepoint" in meta
    assert "event_class: teams" in meta


def test_fixtures_use_expected_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == EXPECTED_SCENARIO_COUNTS[kind]


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_unused_sensitive_grants_match() -> None:
    package = _load_package()
    for scenario in ("pos-1", "pos-2", "pos-3"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_application_activity_suppresses_the_grant() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_benign_grants_do_not_match() -> None:
    package = _load_package()
    for scenario in ("benign-1", "benign-2", "benign-3", "benign-4", "benign-5", "benign-6"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_activity_after_the_window_does_not_suppress_the_grant() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-3"]
    assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
