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


def test_query_uses_session_and_risk_fields() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "session_id" in query
    assert "multiFactorAuthentication" in query
    assert '"is_interactive": false' in query
    assert "risk_level" in query
    assert '"is_interactive": true' in query


def test_correlation_metadata_uses_session_id_and_changed_ip() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-006" in meta
    assert "window_seconds: 3600" in meta
    assert "group_by:\n    - user" in meta
    assert "match_fields:\n        - session_id\n        - src_ip" in meta
    assert (
        "match_fields:\n        - session_id\n      match_changed_fields:\n        - src_ip" in meta
    )
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


def test_session_reuse_from_new_ip_matches() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_same_ip_different_session_or_low_risk_does_not_match() -> None:
    package = _load_package()
    for scenario in ("neg-1", "neg-2", "neg-3"):
        cases = [case for case in package.cases if case.scenario == scenario]
        assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_missing_source_ip_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    replay = next(case for case in cases if not case.event.document.get("is_interactive"))
    replay.event.document.pop("src_ip")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
