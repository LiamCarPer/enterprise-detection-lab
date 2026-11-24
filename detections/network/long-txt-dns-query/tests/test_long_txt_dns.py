from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_long_txt_queries() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "event_class", "dns.query_type", "dns.query_length"):
        assert field in query
    assert "zeek" in query
    assert "TXT" in query
    assert "40" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "zeek" for item in fixtures)


def test_positive_queries_exceed_the_threshold() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    assert all(len(item["event"]["query"]) >= 40 for item in fixtures)


def test_metadata_declares_the_zeek_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-NET-001" in meta
    assert "source: zeek" in meta
    assert "T1071.004" in meta
