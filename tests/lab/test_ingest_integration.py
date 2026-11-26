from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from edl import config
from edl.ingest import (
    OpenSearchClient,
    ingest_cloud,
    ingest_endpoint,
    ingest_identity,
    ingest_kubernetes,
    ingest_network,
    ingest_saas,
)

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


def test_saas_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_saas(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 25, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == [
            "m365-audit",
            "github-audit",
            "exchange-message-trace",
            "m365-dlp",
            "servicenow-approval",
        ]
        assert [result.read for result in first] == [6, 2, 10, 7, 6]
        assert [result.unique for result in first] == [6, 2, 10, 7, 6]
        assert [result.written for result in first] == [6, 2, 10, 7, 6]
        assert first[0].counts == {
            first[0].indices[0]: 4,
            first[0].indices[1]: 2,
        }
        assert first[1].counts == {first[1].indices[0]: 2}
        assert first[2].counts == {
            first[2].indices[0]: 9,
            first[2].indices[1]: 1,
        }
        assert first[3].counts == {index: 1 for index in first[3].indices}
        assert first[4].counts == {
            first[4].indices[0]: 1,
            first[4].indices[1]: 3,
            first[4].indices[2]: 2,
        }

        m365_hits = _search("m365-audit")
        assert len(m365_hits) == 6
        m365_ids = sorted(str(hit["_id"]) for hit in m365_hits)
        m365_event = next(
            hit["_source"]
            for hit in m365_hits
            if hit["_source"]["event_time"] == "2026-11-25T09:00:00Z"
        )
        assert m365_event["event_class"] == "mailbox"
        assert m365_event["action"] == "New-InboxRule"
        assert m365_event["user"] == "analyst@example.test"
        assert m365_event["forward_to"] == "external@example.net"
        assert m365_event["rule_name"] == "Forward external invoices"
        assert m365_event["dedup_origin"] == "declared"

        github_hits = _search("github-audit")
        assert len(github_hits) == 2
        github_ids = sorted(str(hit["_id"]) for hit in github_hits)
        github_event = github_hits[0]["_source"]
        assert github_event["event_class"] == "audit_log"
        assert github_event["action"] == "org.add_member"
        assert github_event["organization"] == "example-org"
        assert github_event["repository"] == "example-org/lab"
        assert github_event["target_user"] == "new-owner"
        assert github_event["dedup_origin"] == "declared"

        exchange_hits = _search("exchange-message-trace")
        assert len(exchange_hits) == 10
        exchange_ids = sorted(str(hit["_id"]) for hit in exchange_hits)
        exchange_event = next(
            hit["_source"]
            for hit in exchange_hits
            if hit["_source"]["event_time"] == "2026-11-01T09:45:00Z"
        )
        assert exchange_event["event_class"] == "redirect"
        assert exchange_event["action"] == "REDIRECT"
        assert exchange_event["trace_event"] == "REDIRECT"
        assert exchange_event["trace_action"] == "Redirect"
        assert exchange_event["sender"] == "vendor@example.net"
        assert exchange_event["recipient"] == "executive@example.test"
        assert exchange_event["subject"] == "Quarterly invoice redirect"
        assert exchange_event["recipient_domains"] == ["example.test"]
        assert exchange_event["external_recipient"] is False
        assert exchange_event["related_recipient"] == "collector@example.org"
        assert exchange_event["related_external"] is True
        assert exchange_event["mailbox"] == "executive@example.test"
        assert exchange_event["delivery_status"] == "Delivered"
        assert exchange_event["directionality"] == "outbound"
        assert exchange_event["result"] == "success"
        assert exchange_event["service"] == "exchange"
        assert exchange_event["source_component"] == "SMTP"
        assert exchange_event["trace_index"] == 1
        assert exchange_event["dedup_origin"] == "declared"

        dlp_hits = _search("m365-dlp")
        assert len(dlp_hits) == 7
        dlp_ids = sorted(str(hit["_id"]) for hit in dlp_hits)
        dlp_event = next(
            hit["_source"]
            for hit in dlp_hits
            if hit["_source"]["event_time"] == "2026-11-01T09:47:00Z"
        )
        assert dlp_event["event_class"] == "dlp_alert"
        assert dlp_event["user"] == "analyst@example.test"
        assert dlp_event["action"] == "External financial data"
        assert dlp_event["policy_name"] == "External financial data"
        assert dlp_event["severity"] == "high"
        assert dlp_event["status"] == "active"
        assert dlp_event["recipient"] == "collector@example.org"
        assert dlp_event["message_id"] == "<20261101094600.102@example.org>"
        assert dlp_event["content_scope"] == "quarterly-invoice.pdf"
        assert dlp_event["service"] == "purview-dlp"
        assert dlp_event["dedup_origin"] == "declared"

        approval_hits = _search("servicenow-approval")
        assert len(approval_hits) == 6
        approval_ids = sorted(str(hit["_id"]) for hit in approval_hits)
        approval_event = next(
            hit["_source"]
            for hit in approval_hits
            if hit["_source"]["event_time"] == "2026-11-20T14:05:00Z"
        )
        assert approval_event["event_class"] == "approval"
        assert approval_event["request_number"] == "REQ0007001"
        assert approval_event["status"] == "closed"
        assert approval_event["decision"] == "denied"
        assert approval_event["mailbox"] == "analyst@example.test"
        assert approval_event["requested_by"] == "analyst@example.test"
        assert approval_event["approver"] == "data-owner@example.test"
        assert approval_event["delivery_recipient"] == "partner@example.org"
        assert approval_event["message_id"] == "<20261120144000.701@example.org>"
        assert approval_event["content_scope"] == "customer-dataset.csv"
        assert approval_event["service"] == "servicenow-approval"
        assert approval_event["dedup_origin"] == "declared"

        approved_event = next(
            hit["_source"]
            for hit in approval_hits
            if hit["_source"]["event_time"] == "2026-11-21T09:15:00Z"
        )
        assert approved_event["decision"] == "approved"
        assert approved_event["status"] == "active"
        assert approved_event["expires_on"] == "2026-12-31T00:00:00Z"
        assert approved_event["approver_role"] == "primary"
        assert approved_event["authority"] == "primary"
        assert approved_event["approval_group"] == "GRP-7002"

        second = ingest_saas(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 26, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert second[0].counts == first[0].counts
        assert second[1].counts == first[1].counts
        assert second[2].counts == first[2].counts
        assert second[3].counts == first[3].counts
        assert second[4].counts == first[4].counts
        assert sorted(str(hit["_id"]) for hit in _search("m365-audit")) == m365_ids
        assert sorted(str(hit["_id"]) for hit in _search("github-audit")) == github_ids
        assert sorted(str(hit["_id"]) for hit in _search("exchange-message-trace")) == exchange_ids
        assert sorted(str(hit["_id"]) for hit in _search("m365-dlp")) == dlp_ids
        assert sorted(str(hit["_id"]) for hit in _search("servicenow-approval")) == approval_ids
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()


def test_network_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_network(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 25, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == ["zeek", "suricata"]
        assert [result.read for result in first] == [4, 5]
        assert all(result.unique == result.read for result in first)
        assert all(result.written == result.read for result in first)

        zeek_hits = _search("zeek")
        assert len(zeek_hits) == 4
        zeek_ids = sorted(str(hit["_id"]) for hit in zeek_hits)
        connection = zeek_hits[0]["_source"]
        assert connection["event_class"] == "conn"
        assert connection["network_log"] == "conn"
        assert connection["network"]["source_ip"] == "10.0.0.5"
        assert connection["network"]["destination_port"] == 443
        assert connection["bytes_sent"] == 812
        assert connection["dedup_origin"] == "declared"

        dns = zeek_hits[1]["_source"]
        assert dns["event_class"] == "dns"
        assert dns["dns"]["query_name"] == "example.test"
        assert dns["dns"]["query_length"] == 12

        suricata_hits = _search("suricata")
        assert len(suricata_hits) == 5
        suricata_ids = sorted(str(hit["_id"]) for hit in suricata_hits)
        alert = suricata_hits[0]["_source"]
        assert alert["event_class"] == "alert"
        assert alert["alert"]["signature"] == "ET MALWARE Example C2 Checkin"
        assert alert["alert"]["severity"] == 1
        assert alert["bytes_received"] == 1840
        assert alert["dedup_origin"] == "declared"

        second = ingest_network(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 26, 12, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.counts[result.indices[0]] for result in second] == [4, 5]
        assert sorted(str(hit["_id"]) for hit in _search("zeek")) == zeek_ids
        assert sorted(str(hit["_id"]) for hit in _search("suricata")) == suricata_ids
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()


def test_kubernetes_ingest_is_idempotent_and_queryable() -> None:
    client = OpenSearchClient()
    try:
        first = ingest_kubernetes(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 25, 14, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.source for result in first] == ["kubernetes-audit", "falco"]
        assert [result.read for result in first] == [3, 2]
        assert all(result.unique == result.read for result in first)

        audit_hits = _search("kubernetes-audit")
        assert len(audit_hits) == 3
        audit_ids = sorted(str(hit["_id"]) for hit in audit_hits)
        audit_event = audit_hits[0]["_source"]
        assert audit_event["event_class"] == "audit"
        assert audit_event["action"] == "create"
        assert audit_event["resource_name"] == "pods"
        assert audit_event["namespace"] == "lab"
        assert audit_event["pod"] == "web-0"
        assert audit_event["result"] == "success"
        assert audit_event["privileged"] is False

        privileged = audit_hits[1]["_source"]
        assert privileged["pod"] == "debug-pod"
        assert privileged["privileged"] is True

        falco_hits = _search("falco")
        assert len(falco_hits) == 2
        falco_ids = sorted(str(hit["_id"]) for hit in falco_hits)
        falco_event = falco_hits[0]["_source"]
        assert falco_event["event_class"] == "runtime_alert"
        assert falco_event["rule_name"] == "Terminal shell in container"
        assert falco_event["namespace"] == "lab"
        assert falco_event["pod"] == "debug-pod"
        assert falco_event["process"]["name"] == "bash"
        assert falco_event["dedup_origin"] == "declared"

        second = ingest_kubernetes(
            config.ROOT,
            client=client,
            ingest_time=datetime(2026, 11, 26, 14, 0, tzinfo=UTC),
            index_prefix=TEST_PREFIX,
        )
        assert [result.counts[result.indices[0]] for result in second] == [3, 2]
        assert sorted(str(hit["_id"]) for hit in _search("kubernetes-audit")) == audit_ids
        assert sorted(str(hit["_id"]) for hit in _search("falco")) == falco_ids
    finally:
        client.delete_matching(f"{TEST_PREFIX}-*")
        client.close()
