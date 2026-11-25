from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 6, "negative": 6, "benign": 2}


def test_query_returns_both_correlation_steps() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "m365-audit" in query
    assert "exchange-message-trace" in query
    assert "forward_external" in query
    assert "external_recipient" in query
    assert "New-InboxRule" in query
    assert "Set-InboxRule" in query
    assert "UpdateInboxRules" in query
    assert '"event_class": "deliver"' in query


def test_correlation_metadata_defines_window_and_steps() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 3600" in meta
    assert "group_by:\n    - mailbox" in meta
    assert "source: m365-audit" in meta
    assert "source: exchange-message-trace" in meta
    assert meta.count("match_fields:\n        - mailbox") == 2
    assert meta.count("- delivery_recipients") == 2
    assert meta.count("match_any_fields:") == 2


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        expected_scenarios = 3 if kind != "benign" else 2
        assert len({item["scenario"] for item in fixtures}) == expected_scenarios


def test_metadata_declares_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-007" in meta
    assert "T1114.003" in meta
    assert "status: tested" in meta


def test_positive_message_trace_events_are_external_deliveries() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    traces = [item for item in fixtures if item["source"] == "exchange-message-trace"]
    assert len(traces) == 3
    for item in traces:
        event = item["event"]
        assert event["Event"] == "DELIVER"
        assert event["Status"] == "Delivered"
        assert event["RecipientAddress"].endswith(("@example.org", "@example.net"))
        assert event["RelatedRecipientAddress"].endswith("@example.test")
        for field in (
            "MessageTraceId",
            "MessageId",
            "SenderAddress",
            "RecipientAddress",
            "Date",
            "Event",
            "Status",
            "RelatedRecipientAddress",
            "TenantId",
        ):
            assert field in event


def test_multiple_forwarding_recipients_match_on_intersection() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    rule = next(
        item for item in fixtures if item["scenario"] == "pos-3" and item["source"] == "m365-audit"
    )
    delivered = next(
        item
        for item in fixtures
        if item["scenario"] == "pos-3" and item["source"] == "exchange-message-trace"
    )
    forward_to = rule["event"]["Parameters"][1]["Value"]
    assert "second@example.net" in forward_to
    assert delivered["event"]["RecipientAddress"] == "second@example.net"


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_recipient_list_intersection_matches_and_mismatch_blocks() -> None:
    package = _load_package()

    positive = [case for case in package.cases if case.scenario == "pos-3"]
    assert _correlation_hit(positive, package.correlation)  # type: ignore[arg-type]

    negative = [case for case in package.cases if case.scenario == "neg-3"]
    assert not _correlation_hit(negative, package.correlation)  # type: ignore[arg-type]


def test_missing_delivery_recipients_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    delivery = next(case for case in cases if case.source == "exchange-message-trace")
    delivery.event.document.pop("delivery_recipients")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
