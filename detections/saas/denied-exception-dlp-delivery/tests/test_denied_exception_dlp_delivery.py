from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 24, "negative": 27, "benign": 3}
EXPECTED_SCENARIO_COUNTS = {"positive": 6, "negative": 7, "benign": 2}


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
    assert '"revoked"' in query
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
    assert "window_seconds: 604800" in meta
    assert "valid_until_field: expires_on" in meta
    assert meta.count("          status: active") == 2
    assert "          authority: primary" in meta
    assert meta.count("        - approval_group") == 2
    assert "min_count: 2" in meta
    assert "distinct_by: approver" in meta


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
    scenarios = sorted({item["scenario"] for item in fixtures})

    for scenario in scenarios:
        items = [item for item in fixtures if item["scenario"] == scenario]
        approval = next(
            item["event"]
            for item in items
            if item["source"] == "servicenow-approval"
            and item["event"]["approval"] in {"Denied", "Revoked"}
        )
        delivery = next(
            item["event"] for item in items if item["source"] == "exchange-message-trace"
        )
        alert = next(item["event"] for item in items if item["source"] == "m365-dlp")
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

    revoked = [case for case in package.cases if case.scenario == "pos-3"]
    assert _correlation_hit(revoked, package.correlation)  # type: ignore[arg-type]

    approved = [case for case in package.cases if case.scenario == "neg-1"]
    assert not _correlation_hit(approved, package.correlation)  # type: ignore[arg-type]

    mismatched = [case for case in package.cases if case.scenario == "neg-2"]
    assert not _correlation_hit(mismatched, package.correlation)  # type: ignore[arg-type]

    scope_mismatch = [case for case in package.cases if case.scenario == "neg-4"]
    assert not _correlation_hit(scope_mismatch, package.correlation)  # type: ignore[arg-type]

    superseded = [case for case in package.cases if case.scenario == "neg-5"]
    assert not _correlation_hit(superseded, package.correlation)  # type: ignore[arg-type]

    late_superseded = [case for case in package.cases if case.scenario == "neg-6"]
    assert not _correlation_hit(late_superseded, package.correlation)  # type: ignore[arg-type]

    expired = [case for case in package.cases if case.scenario == "pos-4"]
    assert _correlation_hit(expired, package.correlation)  # type: ignore[arg-type]

    cancelled = [case for case in package.cases if case.scenario == "pos-5"]
    assert _correlation_hit(cancelled, package.correlation)  # type: ignore[arg-type]

    delegated = [case for case in package.cases if case.scenario == "pos-6"]
    assert _correlation_hit(delegated, package.correlation)  # type: ignore[arg-type]

    renewed = [case for case in package.cases if case.scenario == "neg-7"]
    assert not _correlation_hit(renewed, package.correlation)  # type: ignore[arg-type]


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
