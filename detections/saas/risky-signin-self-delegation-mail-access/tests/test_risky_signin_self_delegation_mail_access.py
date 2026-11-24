from __future__ import annotations

import json
from pathlib import Path

from edl import config
from edl.detection import _correlation_hit, load_detection_package
from edl.telemetry import load_sources

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
    assert "match_fields:" in meta


def test_fixtures_use_paired_scenarios() -> None:
    expected = {"positive": 6, "negative": 9, "benign": 5}
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == expected[kind]
        assert all(item["synthetic"] is True for item in fixtures)
        assert all("scenario" in item for item in fixtures)
        expected_scenarios = 3 if kind == "negative" else 2
        assert len({item["scenario"] for item in fixtures}) == expected_scenarios


def test_metadata_declares_the_detection_identity() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-SAA-005" in meta
    assert "T1114.002" in meta


def _load_package():
    sources = {source.id: source for source in load_sources(config.ROOT)}
    package = load_detection_package(PACKAGE, sources)
    assert package.correlation is not None
    return package


def test_match_fields_require_the_same_mailbox() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "neg-3"]
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]


def test_missing_match_field_blocks_the_sequence() -> None:
    package = _load_package()
    cases = [case for case in package.cases if case.scenario == "pos-1"]
    access = next(case for case in cases if case.event.event_class == "mail_access")
    access.event.document.pop("mailbox")
    assert not _correlation_hit(cases, package.correlation)  # type: ignore[arg-type]
