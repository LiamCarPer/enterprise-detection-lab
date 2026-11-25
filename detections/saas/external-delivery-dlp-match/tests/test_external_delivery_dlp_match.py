from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 4, "negative": 6, "benign": 3}
EXPECTED_SCENARIO_COUNTS = {"positive": 2, "negative": 3, "benign": 2}


def test_query_returns_both_correlation_steps() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "exchange-message-trace" in query
    assert "m365-dlp" in query
    assert '"event_class": "deliver"' in query
    assert '"event_class": "dlp_alert"' in query
    assert "external_recipient" in query
    assert '"severity": "high"' in query
    assert '"status": "active"' in query


def test_correlation_metadata_matches_on_message_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 1800" in meta
    assert "group_by:\n    - message_id" in meta
    assert "source: exchange-message-trace" in meta
    assert "source: m365-dlp" in meta
    assert meta.count("match_fields:\n        - message_id") == 2


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == EXPECTED_SCENARIO_COUNTS[kind]


def test_metadata_declares_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-008" in meta
    assert "T1048.003" in meta
    assert "status: tested" in meta


def test_positive_alerts_describe_the_delivered_message() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    by_scenario: dict[str, dict[str, dict[str, object]]] = {}
    for item in fixtures:
        by_scenario.setdefault(item["scenario"], {})[item["source"]] = item["event"]

    for scenario, events in by_scenario.items():
        delivery = events["exchange-message-trace"]
        alert = events["m365-dlp"]
        assert delivery["Event"] == "DELIVER"
        assert delivery["Status"] == "Delivered"
        assert str(delivery["RecipientAddress"]).endswith(("@example.org", "@example.net"))
        assert alert["Status"] == "Active"
        assert alert["Severity"] == "High"
        assert alert["Workload"] == "Exchange"
        assert str(alert["MessageId"]).lower() == str(delivery["MessageId"]).lower(), scenario


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_message_identity_matches_positive_and_blocks_mismatch() -> None:
    package = _load_package()

    positive = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(positive, package.correlation)  # type: ignore[arg-type]

    negative = [case for case in package.cases if case.scenario == "neg-2"]
    assert not _correlation_hit(negative, package.correlation)  # type: ignore[arg-type]


def test_missing_message_identity_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    alert = next(case for case in cases if case.source == "m365-dlp")
    alert.event.document.pop("message_id")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
