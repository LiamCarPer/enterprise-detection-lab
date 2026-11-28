from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 6, "negative": 12, "benign": 4}
EXPECTED_SCENARIO_COUNTS = {"positive": 3, "negative": 6, "benign": 3}


def test_query_uses_teams_scope_and_app_access_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-audit" in query
    assert "m365-audit" in query
    assert '"approved_app": false' in query
    assert '"sensitive_scope": true' in query
    assert '"scope_categories": "teams"' in query
    assert '"offline_access": true' in query
    assert '"app_access": true' in query
    assert '"MessageRead"' in query
    assert '"MessageSent"' in query


def test_correlation_metadata_uses_application_identity_and_teams() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-011" in meta
    assert "window_seconds: 3600" in meta
    assert "group_by:\n    - app_identity" in meta
    assert "event_class: teams" in meta
    assert "T1528" in meta
    assert "T1213" in meta


def test_fixtures_use_paired_scenarios() -> None:
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


def test_sensitive_teams_grants_followed_by_app_activity_match() -> None:
    package = _load_package()
    for scenario in ("pos-1", "pos-2", "pos-3"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_near_miss_scenarios_do_not_match() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3", "neg-4", "neg-5", "neg-6"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_teams_scope_categories_are_normalized() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    consent = next(case for case in cases if case.source == "entra-audit")
    assert consent.event.document["scope_categories"] == ["teams"]
    assert consent.event.document["sensitive_scope"] is True
    assert consent.event.document["app_identity"] == "contoso chat"


def test_application_teams_activity_is_tagged() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    access = next(case for case in cases if case.source == "m365-audit")
    assert access.event.document["app_identity"] == "contoso chat"
    assert access.event.document["app_access"] is True
    assert access.event.event_class == "teams"


def test_user_teams_activity_is_not_treated_as_an_application() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "neg-4"]
    access = next(case for case in cases if case.source == "m365-audit")
    assert "app_identity" not in access.event.document
    assert access.event.document["app_access"] is False
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_approved_application_consent_is_excluded() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "benign-1"]
    consent = next(case for case in cases if case.source == "entra-audit")
    assert consent.event.document["approved_app"] is True
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
