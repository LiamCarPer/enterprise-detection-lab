from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_mailbox_forwarding_rules() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "action", "result", "forward_to", "forward_external"):
        assert field in query
    assert "must_not" not in query
    assert "example.test" not in query
    assert "New-InboxRule" in query
    assert "Set-InboxRule" in query
    assert "UpdateInboxRules" in query
    assert "m365-audit" in query


def test_before_tuning_query_preserves_the_broad_behavior() -> None:
    before = json.loads((PACKAGE / "queries" / "opensearch-before.json").read_text())
    assert "must_not" not in json.dumps(before)
    assert "forward_to" in json.dumps(before)


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "m365-audit" for item in fixtures)


def test_metadata_declares_the_m365_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-001" in meta
    assert "version: 1.2.1" in meta
    assert "source: m365-audit" in meta
    assert "T1114.003" in meta


def test_one_positive_fixture_uses_update_inbox_rules() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    updates = [item for item in fixtures if item["event"].get("Operation") == "UpdateInboxRules"]
    assert len(updates) == 1
    properties = updates[0]["event"].get("OperationProperties")
    assert isinstance(properties, list)
    assert any(item.get("Name") == "ForwardToRecipientsAction" for item in properties)
