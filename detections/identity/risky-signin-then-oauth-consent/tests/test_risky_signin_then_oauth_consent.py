from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 4, "negative": 8, "benign": 4}
EXPECTED_SCENARIO_COUNTS = {"positive": 2, "negative": 4, "benign": 3}


def test_query_uses_consent_and_signin_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "entra-audit" in query
    assert "risk_level" in query
    assert "singleFactorAuthentication" in query
    assert '"action": "Consent to application"' in query
    assert '"consent_type": "user"' in query
    assert '"offline_access": true' in query
    assert '"resource.type": "ServicePrincipal"' in query
    assert '"approved_app": false' in query


def test_correlation_metadata_uses_a_thirty_minute_window() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-004" in meta
    assert "window_seconds: 1800" in meta
    assert "group_by:\n    - user" in meta
    assert "source: entra-signin" in meta
    assert "source: entra-audit" in meta
    assert "T1078" in meta
    assert "T1528" in meta


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


def test_risky_signin_then_user_consent_matches() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_admin_or_low_risk_consent_does_not_match() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3", "neg-4"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_missing_offline_access_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    consent = next(case for case in cases if case.source == "entra-audit")
    consent.event.document.pop("offline_access")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_approved_app_consent_is_excluded() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "neg-4"]
    consent = next(case for case in cases if case.source == "entra-audit")
    assert consent.event.document["approved_app"] is True
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
