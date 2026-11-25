from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")
EXPECTED_FIXTURE_COUNTS = {"positive": 4, "negative": 4, "benign": 2}


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


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == EXPECTED_FIXTURE_COUNTS[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == 2


def test_metadata_declares_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-007" in meta
    assert "T1114.003" in meta
    assert "status: tested" in meta


def test_positive_message_trace_events_are_external_deliveries() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    traces = [item for item in fixtures if item["source"] == "exchange-message-trace"]
    assert len(traces) == 2
    for item in traces:
        event = item["event"]
        assert event["Event"] == "DELIVER"
        assert event["Status"] == "Delivered"
        assert event["RecipientAddress"].endswith("@example.org")
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
