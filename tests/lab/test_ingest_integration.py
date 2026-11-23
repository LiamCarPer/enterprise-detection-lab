from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from edl import config
from edl.ingest import OpenSearchClient, ingest_cloud, ingest_endpoint, ingest_identity

pytestmark = pytest.mark.lab

TEST_PREFIX = "edl-events-test"


def _search(source: str) -> list[dict[str, object]]:
    response = httpx.post(
        f"{config.OPENSEARCH_URL}/{TEST_PREFIX}-*/_search",
        json={
            "size": 20,
            "query": {"term": {"source": source}},
            "sort": [{"event_time": "asc"}],
        },
        timeout=10.0,
    )
    response.raise_for_status()
    hits = response.json()["hits"]["hits"]
    assert isinstance(hits, list)
    return hits


def test_identity_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_identity(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 22, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == ["entra-signin", "entra-audit"]
        expected = {"entra-signin": 3, "entra-audit": 2}
        assert {result.source: result.read for result in first} == expected
        assert {result.source: result.unique for result in first} == expected
        assert {result.source: result.written for result in first} == expected
        assert {result.source: result.counts[result.indices[0]] for result in first} == expected

        hits_before = _search("entra-signin")
        assert len(hits_before) == 3
        ids_before = sorted(str(hit["_id"]) for hit in hits_before)

        sources = [hit["_source"] for hit in hits_before]
        assert sources[0]["user"] == "analyst@example.test"
        assert sources[0]["app"] == "Office 365"
        assert sources[0]["dedup_origin"] == "declared"
        assert sources[0]["event_class"] == "sign_in"
        assert sources[0]["risk_level"] == "medium"
        assert sources[0]["result"] == "success"
        assert sources[0]["ingest_time"] == "2026-11-22T12:00:00Z"

        second = ingest_identity(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert {result.source: result.counts[result.indices[0]] for result in second} == expected

        hits_after = _search("entra-signin")
        assert sorted(str(hit["_id"]) for hit in hits_after) == ids_before
        assert len(hits_after) == 3

        audit_hits = _search("entra-audit")
        assert len(audit_hits) == 2
        assert audit_hits[0]["_source"]["action"] == "Add service principal"
        assert audit_hits[0]["_source"]["resource"]["name"] == "Lab Reporting App"
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()


def test_endpoint_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_endpoint(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 22, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == ["sysmon", "windows-security"]
        assert all(result.read == 2 for result in first)
        assert all(result.unique == 2 for result in first)
        assert all(result.written == 2 for result in first)
        assert all(result.counts == {result.indices[0]: 2} for result in first)

        sysmon_hits = _search("sysmon")
        assert len(sysmon_hits) == 2
        sysmon_ids = sorted(str(hit["_id"]) for hit in sysmon_hits)
        sysmon_event = sysmon_hits[0]["_source"]
        assert sysmon_event["event_class"] == "process_creation"
        assert sysmon_event["event_code"] == 1
        assert sysmon_event["host"] == "LAB-EP-01"
        assert sysmon_event["user"] == "LAB\\analyst"
        assert sysmon_event["process"]["image"].endswith("whoami.exe")
        assert sysmon_event["dedup_origin"] == "declared"
        assert sysmon_event["dedup_key"]["Channel"] == "Microsoft-Windows-Sysmon/Operational"

        security_hits = _search("windows-security")
        assert len(security_hits) == 2
        security_ids = sorted(str(hit["_id"]) for hit in security_hits)
        security_event = security_hits[0]["_source"]
        assert security_event["event_class"] == "authentication"
        assert security_event["event_code"] == 4624
        assert security_event["action"] == "logon"
        assert security_event["result"] == "success"
        assert security_event["logon_type"] == 3
        assert security_event["dedup_key"]["Channel"] == "Security"

        second = ingest_endpoint(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert all(result.counts == {result.indices[0]: 2} for result in second)
        assert sorted(str(hit["_id"]) for hit in _search("sysmon")) == sysmon_ids
        assert sorted(str(hit["_id"]) for hit in _search("windows-security")) == security_ids
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()


def test_cloud_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_cloud(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 22, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == ["aws-cloudtrail"]
        assert first[0].read == 2
        assert first[0].unique == 2
        assert first[0].written == 2
        assert first[0].counts == {first[0].indices[0]: 2}

        hits = _search("aws-cloudtrail")
        assert len(hits) == 2
        cloud_ids = sorted(str(hit["_id"]) for hit in hits)
        events = [hit["_source"] for hit in hits]

        create_key = events[0]
        assert create_key["event_class"] == "management_event"
        assert create_key["action"] == "CreateAccessKey"
        assert create_key["service"] == "iam.amazonaws.com"
        assert create_key["account"] == "123456789012"
        assert create_key["region"] == "eu-west-1"
        assert create_key["identity_type"] == "IAMUser"
        assert create_key["user"] == "arn:aws:iam::123456789012:user/analyst"
        assert create_key["result"] == "success"
        assert len(create_key["event_id"]) == 36
        assert create_key["dedup_origin"] == "declared"

        stop_logging = events[1]
        assert stop_logging["action"] == "StopLogging"
        assert stop_logging["service"] == "cloudtrail.amazonaws.com"

        second = ingest_cloud(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert second[0].counts == {second[0].indices[0]: 2}
        assert sorted(str(hit["_id"]) for hit in _search("aws-cloudtrail")) == cloud_ids
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()
