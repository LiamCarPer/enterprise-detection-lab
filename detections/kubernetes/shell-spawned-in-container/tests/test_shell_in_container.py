from __future__ import annotations

import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_terminal_shell_alerts() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    for field in ("source", "event_class", "rule_name"):
        assert field in query
    assert "falco" in query
    assert "Terminal shell in container" in query


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "falco" for item in fixtures)


def test_positive_fixtures_use_the_terminal_shell_rule() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    assert all(item["event"]["rule"] == "Terminal shell in container" for item in fixtures)


def test_metadata_declares_the_falco_source() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-K8S-002" in meta
    assert "source: falco" in meta
    assert "T1059" in meta
