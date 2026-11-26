from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 4, "negative": 6, "benign": 4}
EXPECTED_SCENARIO_COUNTS = {"positive": 2, "negative": 3, "benign": 3}


def test_query_uses_location_and_risk_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "country" in query
    assert "multiFactorAuthentication" in query
    assert "risk_level" in query
    assert '"is_interactive": true' in query


def test_correlation_metadata_uses_country_change() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-007" in meta
    assert "window_seconds: 1800" in meta
    assert "group_by:\n    - user" in meta
    assert "match_fields:\n        - country" in meta
    assert "match_changed_fields:\n        - country" in meta
    assert "T1550.001" in meta


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "entra-signin" for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == EXPECTED_SCENARIO_COUNTS[kind]


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_new_country_with_risk_matches() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_same_country_low_risk_or_failed_signin_does_not_match() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_missing_country_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    second = next(case for case in cases if case.event.document.get("risk_level") == "medium")
    second.event.document.pop("country")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
