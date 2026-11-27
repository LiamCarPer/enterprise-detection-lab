from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 4, "negative": 10, "benign": 4}
EXPECTED_SCENARIO_COUNTS = {"positive": 2, "negative": 5, "benign": 3}


def test_query_uses_token_risk_and_mail_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "m365-audit" in query
    assert "anomalousToken" in query
    assert "notprotected" in query
    assert "token_binding_status" in query
    assert "unbound" in query
    assert "long_lived_token" in query
    assert "mail_access" in query
    assert "result" in query


def test_correlation_metadata_uses_token_protection_and_mail_access() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-008" in meta
    assert "window_seconds: 1800" in meta
    assert "group_by:\n    - user" in meta
    assert "risk_event_types: anomalousToken" in meta
    assert "token_protection_status: notprotected" in meta
    assert "token_binding_status: unbound" in meta
    assert "long_lived_token: true" in meta
    assert "source: m365-audit" in meta
    assert "T1528" in meta
    assert "T1114.002" in meta


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


def test_anomalous_token_then_mail_access_matches() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_file_access_other_risk_or_mismatched_user_does_not_match() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3", "neg-4", "neg-5"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_missing_token_protection_state_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    signin = next(case for case in cases if case.source == "entra-signin")
    signin.event.document.pop("token_protection_status")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
