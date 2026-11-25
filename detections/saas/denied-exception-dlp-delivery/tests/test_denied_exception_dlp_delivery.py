from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 6, "negative": 15, "benign": 3}
EXPECTED_SCENARIO_COUNTS = {"positive": 2, "negative": 5, "benign": 2}


def test_query_returns_all_correlation_steps() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "servicenow-approval" in query
    assert "exchange-message-trace" in query
    assert "m365-dlp" in query
    assert '"event_class": "approval"' in query
    assert '"event_class": "deliver"' in query
    assert '"event_class": "dlp_alert"' in query
    assert '"decision": [' in query
    assert '"denied"' in query
    assert '"approved"' in query
    assert "external_recipient" in query


def test_correlation_metadata_uses_required_and_exclusion_steps() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 86400" in meta
    assert "group_by:\n    - delivery_recipient" in meta
    assert "source: servicenow-approval" in meta
    assert "source: exchange-message-trace" in meta
    assert "source: m365-dlp" in meta
    assert meta.count("        - mailbox") == 3
    assert meta.count("        - delivery_recipient") == 3
    assert meta.count("        - message_id") == 3
    assert meta.count("        - content_scope") == 3
    assert meta.count("exclude: true") == 1


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == EXPECTED_SCENARIO_COUNTS[kind]


def test_metadata_declares_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-009" in meta
    assert "T1048.003" in meta
    assert "status: tested" in meta


def test_positive_chain_links_denial_delivery_and_alert() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    by_scenario: dict[str, dict[str, dict[str, object]]] = {}
    for item in fixtures:
        by_scenario.setdefault(item["scenario"], {})[item["source"]] = item["event"]

    for scenario, events in by_scenario.items():
        approval = events["servicenow-approval"]
        delivery = events["exchange-message-trace"]
        alert = events["m365-dlp"]
        assert approval["approval"] == "Denied"
        assert approval["requested_for"] == delivery["RelatedRecipientAddress"]
        assert str(approval["recipient"]).lower() == str(delivery["RecipientAddress"]).lower()
        assert delivery["Event"] == "DELIVER"
        assert delivery["Status"] == "Delivered"
        assert str(alert["MessageId"]).lower() == str(delivery["MessageId"]).lower(), scenario
        assert str(alert["ContentScope"]).lower() == str(approval["content_scope"]).lower(), (
            scenario
        )


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_denied_chain_matches_and_approved_or_mismatched_chain_does_not() -> None:
    package = _load_package()

    positive = [case for case in package.cases if case.scenario == "pos-1"]
    assert _correlation_hit(positive, package.correlation)  # type: ignore[arg-type]

    approved = [case for case in package.cases if case.scenario == "neg-1"]
    assert not _correlation_hit(approved, package.correlation)  # type: ignore[arg-type]

    mismatched = [case for case in package.cases if case.scenario == "neg-2"]
    assert not _correlation_hit(mismatched, package.correlation)  # type: ignore[arg-type]

    scope_mismatch = [case for case in package.cases if case.scenario == "neg-4"]
    assert not _correlation_hit(scope_mismatch, package.correlation)  # type: ignore[arg-type]

    superseded = [case for case in package.cases if case.scenario == "neg-5"]
    assert not _correlation_hit(superseded, package.correlation)  # type: ignore[arg-type]


def test_missing_alert_message_identity_blocks_the_chain() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-2"]
    alert = next(case for case in cases if case.source == "m365-dlp")
    alert.event.document.pop("message_id")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_scope_mismatch_blocks_the_chain() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    alert = next(case for case in cases if case.source == "m365-dlp")
    alert.event.document["content_scope"] = "different-dataset.csv"
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
