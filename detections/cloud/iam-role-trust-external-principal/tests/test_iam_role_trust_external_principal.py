from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote

PACKAGE = Path(__file__).resolve().parents[1]
FIXTURE_KINDS = ("positive", "negative", "benign")


def test_query_targets_external_trust_changes() -> None:
    query = json.dumps(json.loads((PACKAGE / "queries" / "opensearch.json").read_text()))
    assert "aws-cloudtrail" in query
    assert "iam.amazonaws.com" in query
    assert "CreateRole" in query
    assert "UpdateAssumeRolePolicy" in query
    assert '"trust_external": true' in query


def test_metadata_declares_cloudtrail_and_attack_mapping() -> None:
    meta = (PACKAGE / "meta.yaml").read_text()
    assert "id: DET-CLD-003" in meta
    assert "source: aws-cloudtrail" in meta
    assert "T1098.003" in meta
    assert "status: tested" in meta


def test_fixtures_are_synthetic_and_complete() -> None:
    for kind in FIXTURE_KINDS:
        fixtures = json.loads((PACKAGE / "fixtures" / f"{kind}.json").read_text())
        assert len(fixtures) == 5
        assert all(item["synthetic"] is True for item in fixtures)
        assert all(item["source"] == "aws-cloudtrail" for item in fixtures)


def test_positive_fixtures_use_external_or_wildcard_principals() -> None:
    fixtures = json.loads((PACKAGE / "fixtures" / "positive.json").read_text())
    for item in fixtures:
        event = item["event"]
        assert event["eventName"] in {"CreateRole", "UpdateAssumeRolePolicy"}
        assert event["errorCode"] == ""
        document = unquote(event["requestParameters"]["policyDocument"])
        assert "*" in document or "444455556666" in document or "555566667777" in document
