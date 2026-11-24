from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_organization_owner_changes() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "action", "role", "result"):
        assert field in query
    assert "org.add_member" in query
    assert "org.update_member" in query
    assert "admin" in query
    assert "github-audit" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "github-audit" for item in fixtures)


def test_metadata_declares_the_github_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-002" in meta
    assert "source: github-audit" in meta
    assert "T1098" in meta
