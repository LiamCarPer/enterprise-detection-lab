from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_returns_both_correlation_steps() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "m365-audit" in query
    assert "risk_level" in query
    assert "forward_to" in query
    assert "New-InboxRule" in query
    assert "Set-InboxRule" in query
    assert "UpdateInboxRules" in query


def test_correlation_metadata_defines_window_and_steps() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 3600" in meta
    assert "group_by:" in meta
    assert "source: entra-signin" in meta
    assert "source: m365-audit" in meta


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 4
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == 2


def test_metadata_declares_both_sources() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-003" in meta
    assert "T1114.003" in meta


def test_one_positive_fixture_uses_update_inbox_rules() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    updates = [item for item in fixtures if item["event"].get("Operation") == "UpdateInboxRules"]
    assert len(updates) == 1
    assert updates[0]["event"]["OperationProperties"][0]["Name"] == ("RedirectToRecipientsAction")
