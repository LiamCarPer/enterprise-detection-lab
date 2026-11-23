from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_service_principal_owner_events() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "action", "result", "resource.type"):
        assert field in query
    assert "Add owner to service principal" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "entra-audit" for item in fixtures)


def test_metadata_declares_the_audit_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-IDN-002" in meta
    assert "source: entra-audit" in meta
    assert "T1098.002" in meta
