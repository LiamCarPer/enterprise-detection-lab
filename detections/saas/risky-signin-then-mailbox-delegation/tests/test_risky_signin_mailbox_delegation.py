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
    assert "Add-MailboxPermission" in query
    assert "Add-MailboxFolderPermission" in query
    assert "FullAccess" in query
    assert "PublishingEditor" in query


def test_correlation_metadata_defines_window_and_steps() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "window_seconds: 3600" in meta
    assert "group_by:" in meta
    assert "source: entra-signin" in meta
    assert "source: m365-audit" in meta


def test_fixtures_use_paired_scenarios() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 6
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        assert len({item["scenario"] for item in fixtures}) == 3


def test_metadata_declares_the_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-004" in meta
    assert "T1114.002" in meta


def test_one_positive_fixture_uses_folder_permission() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    folders = [
        item for item in fixtures if item["event"].get("Operation") == "Add-MailboxFolderPermission"
    ]
    assert len(folders) == 1
    assert folders[0]["event"]["Parameters"][2]["Value"] == "Editor"
