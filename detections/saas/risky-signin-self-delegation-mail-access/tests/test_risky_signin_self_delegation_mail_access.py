from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_returns_all_three_correlation_steps() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "entra-signin" in query
    assert "m365-audit" in query
    assert "risk_level" in query
    assert "self_delegation" in query
    assert "MailItemsAccessed" in query


def test_correlation_metadata_defines_three_steps() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 3600" in meta
    assert "group_by:" in meta
    assert "event_class: sign_in" in meta
    assert "event_class: mailbox_permission" in meta
    assert "event_class: mail_access" in meta


def test_fixtures_use_paired_scenarios() -> None:
    expected = {"positive": 6, "negative": 6, "benign": 5}
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == expected[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == 2


def test_metadata_declares_the_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-005" in meta
    assert "T1114.002" in meta
