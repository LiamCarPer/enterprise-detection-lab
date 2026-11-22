from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from edl import config
from edl.ingest import OpenSearchClient, ingest_endpoint, ingest_identity

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
        assert all(result.read == 2 for result in first)
        assert all(result.unique == 2 for result in first)
        assert all(result.written == 2 for result in first)
        assert all(result.counts == {result.indices[0]: 2} for result in first)

        hits_before = _search("entra-signin")
        assert len(hits_before) == 2
        ids_before = sorted(str(hit["_id"]) for hit in hits_before)

        sources = [hit["_source"] for hit in hits_before]
        assert sources[0]["user"] == "analyst@example.test"
        assert sources[0]["app"] == "Office 365"
        assert sources[0]["dedup_origin"] == "declared"
        assert sources[0]["event_class"] == "sign_in"
        assert sources[0]["ingest_time"] == "2026-11-22T12:00:00Z"

        second = ingest_identity(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 23, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert all(result.counts == {result.indices[0]: 2} for result in second)

        hits_after = _search("entra-signin")
        assert sorted(str(hit["_id"]) for hit in hits_after) == ids_before
        assert len(hits_after) == 2

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
