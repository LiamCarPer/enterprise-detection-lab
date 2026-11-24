from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_mailbox_forwarding_rules() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "action", "result", "forward_to", "forward_domain"):
        assert field in query
    assert "must_not" in query
    assert "example.test" in query
    assert "New-InboxRule" in query
    assert "Set-InboxRule" in query
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
    assert "version: 1.1.0" in meta
    assert "source: m365-audit" in meta
    assert "T1114.003" in meta
