from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_office_and_scripting_hosts() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "event_code", "process.parent_name", "process.name"):
        assert field in query
    assert "winword.exe" in query
    assert "powershell.exe" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "sysmon" for item in fixtures)


def test_metadata_declares_the_sysmon_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-END-002" in meta
    assert "source: sysmon" in meta
    assert "T1566.001" in meta
