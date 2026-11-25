from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from edl.errors import IngestError
from edl.ingest import (
    CLASSIFIERS,
    CanonicalEvent,
    classify_exchange_message_trace,
    classify_github_audit,
    classify_m365_audit,
    classify_suricata,
    classify_sysmon,
    classify_windows_security,
    classify_zeek,
    dedup_fingerprint,
    deduplicate_events,
    format_timestamp,
    index_name,
    ingest_cloud,
    ingest_domain,
    ingest_endpoint,
    ingest_identity,
    ingest_kubernetes,
    ingest_network,
    ingest_saas,
    ingest_source,
    load_cloud_sources,
    load_dataset,
    load_domain_sources,
    load_endpoint_sources,
    load_identity_sources,
    load_kubernetes_sources,
    load_network_sources,
    load_saas_sources,
    normalize_aws_cloudtrail,
    normalize_dataset,
    normalize_entra_audit,
    normalize_entra_signin,
    normalize_event,
    normalize_exchange_message_trace,
    normalize_falco,
    normalize_github_audit,
    normalize_kubernetes_audit,
    normalize_m365_audit,
    normalize_m365_dlp,
    normalize_servicenow_approval,
    normalize_suricata,
    normalize_sysmon,
    normalize_windows_security,
    normalize_zeek,
    parse_timestamp,
    write_events,
)
from edl.telemetry import TelemetrySource

SIGNIN_RAW = {
    "id": "00000000-0000-4000-8000-000000000001",
    "createdDateTime": "2026-11-01T09:00:00Z",
    "userPrincipalName": "analyst@example.test",
    "appDisplayName": "Office 365",
    "ipAddress": "203.0.113.10",
    "status": "success",
    "authenticationRequirement": "singleFactorAuthentication",
    "isInteractive": True,
    "conditionalAccessStatus": "success",
    "riskLevelDuringSignIn": "none",
    "deviceDetail": {"operatingSystem": "Windows 11", "browser": "Edge"},
}

AUDIT_RAW = {
    "id": "00000000-0000-4000-8000-000000000101",
    "activityDateTime": "2026-11-01T09:10:00Z",
    "operationName": "Add service principal",
    "initiatedBy": {"user": {"userPrincipalName": "admin@example.test"}},
    "targetResources": [{"displayName": "Lab Reporting App", "type": "ServicePrincipal"}],
    "result": "success",
}


def _source(source_id: str = "entra-signin", **overrides: object) -> TelemetrySource:
    signin = source_id == "entra-signin"
    data: dict[str, object] = {
        "id": source_id,
        "name": "Synthetic identity source",
        "provider": "Microsoft",
        "product": "Entra ID",
        "event_classes": ["sign_in" if signin else "audit"],
        "schema_version": "1.0",
        "status": "sampled",
        "owner": "detection-engineering",
        "event_time_field": "createdDateTime" if signin else "activityDateTime",
        "ingest_time_field": "ingest_time",
        "timezone": "UTC",
        "ordering": "unordered",
        "dedup_key": ["id"],
        "required_fields": ["id", "createdDateTime" if signin else "activityDateTime"],
        "known_gaps": [],
    }
    data.update(overrides)
    return TelemetrySource(Path(f"{source_id}.yaml"), data)


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[tuple[str, dict[str, object]]], bool]] = []
        self.documents: dict[str, int] = {}

    def bulk(
        self,
        index: str,
        actions: list[tuple[str, dict[str, object]]],
        *,
        refresh: bool,
    ) -> None:
        self.calls.append((index, actions, refresh))
        self.documents[index] = self.documents.get(index, 0) + len(actions)

    def count(self, index: str) -> int:
        return self.documents.get(index, 0)


def _write_dataset(tmp_path: Path, events: list[object], *, name: str = "data.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(events), encoding="utf-8")
    return path


def test_parse_timestamp_normalizes_offsets() -> None:
    parsed = parse_timestamp(
        "2026-11-01T10:30:00+01:00",
        source="entra-signin",
        field="createdDateTime",
    )
    assert parsed == datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
    assert format_timestamp(parsed) == "2026-11-01T09:30:00Z"


@pytest.mark.parametrize(
    "value",
    [None, "", "not-a-time", "2026-11-01T09:00:00"],
)
def test_parse_timestamp_rejects_invalid_values(value: object) -> None:
    with pytest.raises(IngestError, match="createdDateTime"):
        parse_timestamp(value, source="entra-signin", field="createdDateTime")


def test_normalize_entra_signin_maps_identity_fields() -> None:
    document = normalize_entra_signin(SIGNIN_RAW)
    assert document["user"] == "analyst@example.test"
    assert document["src_ip"] == "203.0.113.10"
    assert document["app"] == "Office 365"
    assert document["auth_requirement"] == "singleFactorAuthentication"
    assert document["is_interactive"] is True
    assert document["device"] == {"os": "Windows 11", "browser": "Edge"}


def test_normalize_entra_signin_omits_empty_device() -> None:
    document = normalize_entra_signin({**SIGNIN_RAW, "deviceDetail": {}})
    assert "device" not in document


def test_normalize_entra_audit_maps_initiator_and_resource() -> None:
    document = normalize_entra_audit(AUDIT_RAW)
    assert document["user"] == "admin@example.test"
    assert document["action"] == "Add service principal"
    assert document["result"] == "success"
    assert document["resource"] == {
        "name": "Lab Reporting App",
        "type": "ServicePrincipal",
        "count": 1,
    }


def test_normalize_entra_audit_falls_back_to_app_identity() -> None:
    raw = {
        "operationName": "Consent to application",
        "initiatedBy": {"app": {"displayName": "Lab App"}},
        "result": "success",
    }
    document = normalize_entra_audit(raw)
    assert document["user"] == "Lab App"
    assert document["app"] == "Lab App"
    assert "resource" not in document


def test_normalize_entra_audit_ignores_malformed_nested_fields() -> None:
    document = normalize_entra_audit(
        {
            "operationName": "Update user",
            "initiatedBy": "not-a-mapping",
            "targetResources": ["not-a-mapping"],
            "result": "success",
        }
    )
    assert document == {
        "action": "Update user",
        "result": "success",
    }


def test_dedup_fingerprint_is_deterministic_for_declared_key() -> None:
    first = dedup_fingerprint("entra-signin", ["id"], SIGNIN_RAW)
    second = dedup_fingerprint("entra-signin", ["id"], SIGNIN_RAW)
    assert first == second
    assert first[1] == {"id": SIGNIN_RAW["id"]}
    assert first[2] == "declared"

    changed = dedup_fingerprint("entra-signin", ["id"], {**SIGNIN_RAW, "id": "other"})
    assert changed[0] != first[0]


def test_dedup_fingerprint_supports_dotted_keys() -> None:
    fingerprint = dedup_fingerprint(
        "entra-audit",
        ["initiatedBy.user.userPrincipalName"],
        AUDIT_RAW,
    )
    assert fingerprint[1] == {"initiatedBy.user.userPrincipalName": "admin@example.test"}
    assert fingerprint[2] == "declared"


def test_dedup_fingerprint_falls_back_to_hash() -> None:
    without_id = {key: value for key, value in SIGNIN_RAW.items() if key != "id"}
    first = dedup_fingerprint("entra-signin", ["id"], without_id)
    second = dedup_fingerprint("entra-signin", ["id"], without_id)
    assert first == second
    assert first[1] == {}
    assert first[2] == "hash"

    changed = dedup_fingerprint("entra-signin", ["id"], {**without_id, "status": "failure"})
    assert changed[0] != first[0]


def test_normalize_event_builds_canonical_document() -> None:
    ingest_time = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
    event = normalize_event(_source(), SIGNIN_RAW, ingest_time=ingest_time)
    assert event.source == "entra-signin"
    assert event.event_class == "sign_in"
    assert event.event_time == datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
    assert event.document["@timestamp"] == "2026-11-01T09:00:00Z"
    assert event.document["ingest_time"] == "2026-11-22T12:00:00Z"
    assert event.document["raw"] == SIGNIN_RAW
    assert event.document["dedup_origin"] == "declared"
    assert event.document["schema_version"] == "1.0"


def test_normalize_event_tolerates_missing_required_fields_contract() -> None:
    source = _source(required_fields="id")
    event = normalize_event(
        source,
        SIGNIN_RAW,
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert event.source == "entra-signin"


def test_normalize_event_rejects_missing_required_field() -> None:
    with pytest.raises(IngestError, match="missing required field"):
        normalize_event(
            _source(),
            {"createdDateTime": "2026-11-01T09:00:00Z"},
            ingest_time=datetime.now(UTC),
        )


def test_normalize_event_rejects_unknown_source() -> None:
    source = _source("unknown-source")
    with pytest.raises(IngestError, match="No normalizer"):
        normalize_event(source, SIGNIN_RAW, ingest_time=datetime.now(UTC))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"event_time_field": ""}, "event_time_field"),
        ({"dedup_key": []}, "dedup_key"),
        ({"event_classes": []}, "event_classes"),
    ],
)
def test_normalize_event_rejects_incomplete_contract(
    overrides: dict[str, object], message: str
) -> None:
    source = _source(**overrides)
    with pytest.raises(IngestError, match=message):
        normalize_event(source, SIGNIN_RAW, ingest_time=datetime.now(UTC))


def test_normalize_dataset_reports_item_position() -> None:
    source = _source()
    with pytest.raises(IngestError, match="dataset item 2"):
        normalize_dataset(
            source,
            [SIGNIN_RAW, {**SIGNIN_RAW, "id": ""}],
            ingest_time=datetime.now(UTC),
        )


def test_normalize_dataset_rejects_non_object_item() -> None:
    with pytest.raises(IngestError, match="must be an object"):
        normalize_dataset(
            _source(),
            ["not-an-object"],
            ingest_time=datetime.now(UTC),
        )


def test_deduplicate_events_keeps_first_occurrence() -> None:
    first = CanonicalEvent(
        source="entra-signin",
        event_class="sign_in",
        event_time=datetime(2026, 11, 1, tzinfo=UTC),
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        document={"id": 1},
        dedup_id="same",
    )
    second = CanonicalEvent(
        source="entra-signin",
        event_class="sign_in",
        event_time=datetime(2026, 11, 2, tzinfo=UTC),
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        document={"id": 2},
        dedup_id="same",
    )
    unique, duplicates = deduplicate_events([first, second])
    assert unique == [first]
    assert duplicates == 1


def test_index_name_uses_event_time_in_utc() -> None:
    assert (
        index_name(
            "edl-events",
            "entra-signin",
            datetime(2026, 11, 1, 0, 30, tzinfo=UTC),
        )
        == "edl-events-entra-signin-2026.11.01"
    )


def test_load_dataset_checks_hash_and_shape(tmp_path: Path) -> None:
    path = _write_dataset(tmp_path, [SIGNIN_RAW], name="identity.json")
    from edl.utils import sha256_file

    source = _source(
        sample_data={
            "path": "identity.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
            "sha256": sha256_file(path),
        }
    )
    loaded_path, events = load_dataset(source, tmp_path)
    assert loaded_path == path
    assert events == [SIGNIN_RAW]


def test_load_dataset_rejects_hash_mismatch(tmp_path: Path) -> None:
    _write_dataset(tmp_path, [SIGNIN_RAW])
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
            "sha256": "0" * 64,
        }
    )
    with pytest.raises(IngestError, match="hash does not match"):
        load_dataset(source, tmp_path)


def test_load_dataset_requires_sample_contract(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="no sample_data"):
        load_dataset(_source(), tmp_path)


def test_load_dataset_rejects_empty_path(tmp_path: Path) -> None:
    source = _source(sample_data={"path": ""})
    with pytest.raises(IngestError, match="sample_data.path"):
        load_dataset(source, tmp_path)


def test_load_dataset_rejects_missing_file(tmp_path: Path) -> None:
    source = _source(
        sample_data={
            "path": "missing.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    with pytest.raises(IngestError, match="not found"):
        load_dataset(source, tmp_path)


def test_load_dataset_rejects_invalid_json(tmp_path: Path) -> None:
    (tmp_path / "data.json").write_text("{", encoding="utf-8")
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    with pytest.raises(IngestError, match="cannot read sample dataset"):
        load_dataset(source, tmp_path)


@pytest.mark.parametrize("payload", [{"event": "not-a-list"}, []])
def test_load_dataset_requires_non_empty_array(tmp_path: Path, payload: object) -> None:
    _write_dataset(tmp_path, payload)  # type: ignore[arg-type]
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    with pytest.raises(IngestError, match="non-empty JSON array"):
        load_dataset(source, tmp_path)


def test_write_events_batches_and_counts() -> None:
    client = FakeClient()
    events = []
    for index, source_id in enumerate(("entra-signin", "entra-signin", "entra-audit")):
        events.append(
            CanonicalEvent(
                source=source_id,
                event_class="sign_in" if source_id == "entra-signin" else "audit",
                event_time=datetime(2026, 11, 1, tzinfo=UTC),
                ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
                document={"sequence": index},
                dedup_id=f"id-{index}",
            )
        )

    written, counts = write_events(
        client,  # type: ignore[arg-type]
        events,
        index_prefix="edl-events",
        refresh=True,
        batch_size=1,
    )
    assert written == 3
    assert counts == {
        "edl-events-entra-audit-2026.11.01": 1,
        "edl-events-entra-signin-2026.11.01": 2,
    }
    assert len(client.calls) == 3
    assert all(call[2] is True for call in client.calls)


def test_write_events_can_skip_counts_without_refresh() -> None:
    client = FakeClient()
    event = CanonicalEvent(
        source="entra-signin",
        event_class="sign_in",
        event_time=datetime(2026, 11, 1, tzinfo=UTC),
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        document={},
        dedup_id="id",
    )
    written, counts = write_events(
        client,  # type: ignore[arg-type]
        [event],
        index_prefix="edl-events",
        refresh=False,
        batch_size=10,
    )
    assert written == 1
    assert counts == {}


def test_write_events_rejects_invalid_batch_size() -> None:
    with pytest.raises(IngestError, match="batch_size"):
        write_events(
            FakeClient(),  # type: ignore[arg-type]
            [],
            index_prefix="edl-events",
            refresh=True,
            batch_size=0,
        )


def test_ingest_source_dry_run(tmp_path: Path) -> None:
    _write_dataset(tmp_path, [SIGNIN_RAW, {**SIGNIN_RAW, "id": "second"}])
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    result = ingest_source(
        source,
        tmp_path,
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        dry_run=True,
    )
    assert result.read == 2
    assert result.unique == 2
    assert result.duplicates == 0
    assert result.written == 0
    assert result.counts == {}
    assert result.mode == "dry-run"
    assert result.indices == ("edl-events-entra-signin-2026.11.01",)


def test_ingest_source_writes_with_client(tmp_path: Path) -> None:
    _write_dataset(tmp_path, [SIGNIN_RAW, SIGNIN_RAW])
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    client = FakeClient()
    result = ingest_source(
        source,
        tmp_path,
        client=client,  # type: ignore[arg-type]
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert result.read == 2
    assert result.unique == 1
    assert result.duplicates == 1
    assert result.written == 1
    assert result.mode == "ingested"
    assert result.counts == {"edl-events-entra-signin-2026.11.01": 1}
    assert result.to_dict()["source"] == "entra-signin"


def test_ingest_source_opens_client_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_dataset(tmp_path, [SIGNIN_RAW])
    source = _source(
        sample_data={
            "path": "data.json",
            "synthetic": True,
            "license": "synthetic",
            "provenance": "generated for test",
        }
    )
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    result = ingest_source(
        source,
        tmp_path,
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert result.written == 1


def test_load_identity_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_identity_sources()] == [
        "entra-signin",
        "entra-audit",
    ]
    assert [source.id for source in load_identity_sources(requested=("entra-audit",))] == [
        "entra-audit"
    ]
    assert [
        source.id for source in load_identity_sources(requested=("entra-audit", "entra-audit"))
    ] == ["entra-audit"]


def test_load_identity_sources_rejects_unknown() -> None:
    with pytest.raises(IngestError, match="Unknown telemetry source"):
        load_identity_sources(requested=("missing",))


def test_load_identity_sources_rejects_non_identity() -> None:
    with pytest.raises(IngestError, match="Not identity source"):
        load_identity_sources(requested=("sysmon",))


def test_ingest_identity_dry_run_uses_repository_samples() -> None:
    results = ingest_identity(dry_run=True)
    assert [result.source for result in results] == ["entra-signin", "entra-audit"]
    assert {result.source: result.read for result in results} == {
        "entra-signin": 3,
        "entra-audit": 2,
    }
    assert {result.source: result.unique for result in results} == {
        "entra-signin": 3,
        "entra-audit": 2,
    }
    assert all(result.written == 0 for result in results)


def test_ingest_identity_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_identity(
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 2
    assert all(result.mode == "ingested" for result in results)
    assert all(result.counts for result in results)


SYSMON_RAW = {
    "UtcTime": "2026-11-01T09:15:00Z",
    "EventID": 1,
    "Computer": "LAB-EP-01",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "EventRecordID": 1001,
    "ProcessGuid": "{00000000-0000-4000-8000-000000000201}",
    "ProcessId": 4242,
    "Image": "C:\\Windows\\System32\\whoami.exe",
    "CommandLine": "whoami /all",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe /c whoami /all",
    "User": "LAB\\analyst",
}

SECURITY_RAW = {
    "TimeCreated": "2026-11-01T09:20:00Z",
    "EventID": 4624,
    "Computer": "LAB-EP-01",
    "Channel": "Security",
    "EventRecordID": 2001,
    "TargetUserName": "analyst",
    "IpAddress": "203.0.113.10",
    "LogonType": 3,
    "Status": "0x0",
    "SubjectUserName": "-",
    "ServiceName": "-",
    "TaskName": "-",
}


def _endpoint_source(source_id: str = "sysmon", **overrides: object) -> TelemetrySource:
    sysmon = source_id == "sysmon"
    data: dict[str, object] = {
        "id": source_id,
        "name": "Synthetic endpoint source",
        "provider": "Microsoft",
        "product": "Sysmon" if sysmon else "Windows",
        "event_classes": (
            ["process_creation", "network_connection", "other"]
            if sysmon
            else ["authentication", "account_management", "other"]
        ),
        "schema_version": "1.0",
        "status": "sampled",
        "owner": "detection-engineering",
        "event_time_field": "UtcTime" if sysmon else "TimeCreated",
        "ingest_time_field": "ingest_time",
        "timezone": "UTC",
        "ordering": "unordered",
        "dedup_key": ["EventRecordID", "Computer", "Channel"],
        "required_fields": [
            "EventID",
            "Computer",
            "EventRecordID",
            "Channel",
            "UtcTime" if sysmon else "TimeCreated",
        ],
        "known_gaps": [],
    }
    data.update(overrides)
    return TelemetrySource(Path(f"{source_id}.yaml"), data)


@pytest.mark.parametrize(
    ("event_id", "expected"),
    [
        (1, "process_creation"),
        (3, "network_connection"),
        (10, "process_access"),
        (11, "file_create"),
        (12, "registry_set"),
        (13, "registry_set"),
        (14, "registry_set"),
        (22, "dns_query"),
        (999, "other"),
    ],
)
def test_classify_sysmon_maps_event_ids(event_id: int, expected: str) -> None:
    assert classify_sysmon({"EventID": event_id}) == expected


def test_classify_sysmon_handles_invalid_event_id() -> None:
    assert classify_sysmon({"EventID": "not-an-int"}) == "other"
    assert classify_sysmon({"EventID": True}) == "other"
    assert classify_sysmon({}) == "other"
    assert classify_sysmon({"EventID": 1.5}) == "other"


@pytest.mark.parametrize(
    ("event_id", "expected"),
    [
        (4624, "authentication"),
        (4625, "authentication"),
        (4720, "account_management"),
        (4740, "account_management"),
        (999, "other"),
    ],
)
def test_classify_windows_security_maps_event_ids(event_id: int, expected: str) -> None:
    assert classify_windows_security({"EventID": event_id}) == expected


def test_classify_windows_security_handles_invalid_event_id() -> None:
    assert classify_windows_security({"EventID": "bad"}) == "other"
    assert classify_windows_security({}) == "other"


def test_normalize_sysmon_process_event() -> None:
    document = normalize_sysmon(SYSMON_RAW)
    assert document["host"] == "LAB-EP-01"
    assert document["user"] == "LAB\\analyst"
    assert document["event_code"] == 1
    assert document["process"] == {
        "name": "whoami.exe",
        "image": "C:\\Windows\\System32\\whoami.exe",
        "command_line": "whoami /all",
        "guid": "{00000000-0000-4000-8000-000000000201}",
        "id": 4242,
        "parent_name": "cmd.exe",
        "parent_image": "C:\\Windows\\System32\\cmd.exe",
        "parent_command_line": "cmd.exe /c whoami /all",
    }


def test_normalize_sysmon_maps_network_file_registry_and_dns() -> None:
    document = normalize_sysmon(
        {
            "EventID": 3,
            "Computer": "LAB-EP-01",
            "SourceIp": "10.0.0.5",
            "SourcePort": 50000,
            "DestinationIp": "198.51.100.25",
            "DestinationPort": 443,
            "Protocol": "tcp",
            "TargetFilename": "C:\\Temp\\out.bin",
            "TargetObject": "HKLM\\Software\\Run\\Lab",
            "Details": "C:\\Temp\\out.bin",
            "QueryName": "example.test",
            "QueryResults": "203.0.113.10",
        }
    )
    assert document["network"] == {
        "source_ip": "10.0.0.5",
        "source_port": 50000,
        "destination_ip": "198.51.100.25",
        "destination_port": 443,
        "protocol": "tcp",
    }
    assert document["file"] == {"target_filename": "C:\\Temp\\out.bin"}
    assert document["registry"] == {
        "target_object": "HKLM\\Software\\Run\\Lab",
        "details": "C:\\Temp\\out.bin",
    }
    assert document["dns"] == {
        "query_name": "example.test",
        "query_results": "203.0.113.10",
    }


def test_normalize_windows_security_successful_logon() -> None:
    document = normalize_windows_security(SECURITY_RAW)
    assert document["host"] == "LAB-EP-01"
    assert document["user"] == "analyst"
    assert document["event_code"] == 4624
    assert document["action"] == "logon"
    assert document["result"] == "success"
    assert document["src_ip"] == "203.0.113.10"
    assert document["logon_type"] == 3
    assert document["status"] == "0x0"
    assert "subject_user" not in document
    assert "service_name" not in document
    assert "task_name" not in document


def test_normalize_windows_security_failure_and_account_management() -> None:
    failure = normalize_windows_security({**SECURITY_RAW, "EventID": 4625})
    assert failure["action"] == "logon_failure"
    assert failure["result"] == "failure"

    created = normalize_windows_security(
        {
            **SECURITY_RAW,
            "EventID": 4720,
            "TargetUserName": "new-user",
            "SubjectUserName": "admin",
        }
    )
    assert created["action"] == "user_created"
    assert "result" not in created
    assert created["subject_user"] == "admin"


def test_normalize_event_endpoint_uses_classifier_and_declared_key() -> None:
    event = normalize_event(
        _endpoint_source(),
        SYSMON_RAW,
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert event.event_class == "process_creation"
    assert event.document["event_class"] == "process_creation"
    assert event.document["dedup_origin"] == "declared"
    assert event.document["dedup_key"]["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event.document["process"]["image"].endswith("whoami.exe")


def test_normalize_event_endpoint_marks_unknown_event_class_other() -> None:
    event = normalize_event(
        _endpoint_source(),
        {**SYSMON_RAW, "EventID": 999},
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert event.event_class == "other"


def test_normalize_event_rejects_undeclared_classifier_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(CLASSIFIERS, "entra-signin", lambda _raw: "bogus")
    with pytest.raises(IngestError, match="undeclared event class"):
        normalize_event(
            _source(),
            SIGNIN_RAW,
            ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        )


def test_load_endpoint_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_endpoint_sources()] == [
        "sysmon",
        "windows-security",
    ]
    assert [source.id for source in load_endpoint_sources(requested=("sysmon",))] == ["sysmon"]


def test_load_endpoint_sources_rejects_non_endpoint() -> None:
    with pytest.raises(IngestError, match="Not endpoint source"):
        load_endpoint_sources(requested=("entra-signin",))


def test_load_domain_sources_rejects_unknown_domain() -> None:
    with pytest.raises(IngestError, match="Unknown ingest domain"):
        load_domain_sources("mobile")


def test_ingest_endpoint_dry_run_uses_repository_samples() -> None:
    results = ingest_endpoint(dry_run=True)
    assert [result.source for result in results] == ["sysmon", "windows-security"]
    assert all(result.read == 2 for result in results)
    assert all(result.unique == 2 for result in results)
    assert results[0].indices == ("edl-events-sysmon-2026.11.01",)
    assert results[1].indices == ("edl-events-windows-security-2026.11.01",)


def test_ingest_domain_dry_run_accepts_endpoint() -> None:
    results = ingest_domain("endpoint", dry_run=True, sources=("sysmon",))
    assert [result.source for result in results] == ["sysmon"]


def test_ingest_endpoint_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_endpoint(
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 2
    assert all(result.mode == "ingested" for result in results)
    assert all(result.counts for result in results)


CLOUDTRAIL_RAW = {
    "eventTime": "2026-11-01T09:25:00Z",
    "eventVersion": "1.11",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "eu-west-1",
    "sourceIPAddress": "203.0.113.10",
    "userAgent": "aws-cli/2.0",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/analyst",
    },
    "requestParameters": {"userName": "analyst"},
    "responseElements": {"accessKey": {"accessKeyId": "EXAMPLE", "status": "Active"}},
    "errorCode": "",
    "errorMessage": "",
    "eventID": "00000000-0000-4000-8000-000000000301",
    "recipientAccountId": "123456789012",
}


def _cloud_source(**overrides: object) -> TelemetrySource:
    data: dict[str, object] = {
        "id": "aws-cloudtrail",
        "name": "AWS CloudTrail management events",
        "provider": "Amazon Web Services",
        "product": "CloudTrail",
        "event_classes": ["management_event", "api_activity"],
        "schema_version": "1.0",
        "status": "sampled",
        "owner": "detection-engineering",
        "event_time_field": "eventTime",
        "ingest_time_field": "ingest_time",
        "timezone": "UTC",
        "ordering": "unordered",
        "dedup_key": ["eventID"],
        "required_fields": [
            "eventTime",
            "eventSource",
            "eventName",
            "userIdentity",
            "sourceIPAddress",
            "recipientAccountId",
            "eventID",
        ],
        "known_gaps": [],
    }
    data.update(overrides)
    return TelemetrySource(Path("aws-cloudtrail.yaml"), data)


def test_normalize_aws_cloudtrail_maps_identity_and_request_context() -> None:
    document = normalize_aws_cloudtrail(CLOUDTRAIL_RAW)
    assert document["user"] == "arn:aws:iam::123456789012:user/analyst"
    assert document["identity_type"] == "IAMUser"
    assert document["identity_arn"] == "arn:aws:iam::123456789012:user/analyst"
    assert document["action"] == "CreateAccessKey"
    assert document["service"] == "iam.amazonaws.com"
    assert document["account"] == "123456789012"
    assert document["region"] == "eu-west-1"
    assert document["src_ip"] == "203.0.113.10"
    assert document["event_id"] == "00000000-0000-4000-8000-000000000301"
    assert document["result"] == "success"
    assert "error_code" not in document


def test_normalize_aws_cloudtrail_marks_error_as_failure() -> None:
    document = normalize_aws_cloudtrail({**CLOUDTRAIL_RAW, "errorCode": "AccessDenied"})
    assert document["result"] == "failure"
    assert document["error_code"] == "AccessDenied"


def test_normalize_aws_cloudtrail_handles_missing_identity() -> None:
    document = normalize_aws_cloudtrail({**CLOUDTRAIL_RAW, "userIdentity": "not-a-mapping"})
    assert "user" not in document
    assert "identity_type" not in document
    assert "identity_arn" not in document


def test_normalize_event_cloudtrail_uses_declared_key_and_event_class() -> None:
    event = normalize_event(
        _cloud_source(),
        CLOUDTRAIL_RAW,
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
    )
    assert event.event_class == "management_event"
    assert event.document["event_class"] == "management_event"
    assert event.document["dedup_origin"] == "declared"
    assert event.document["dedup_key"] == {"eventID": "00000000-0000-4000-8000-000000000301"}


def test_load_cloud_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_cloud_sources()] == ["aws-cloudtrail"]
    assert [source.id for source in load_cloud_sources(requested=("aws-cloudtrail",))] == [
        "aws-cloudtrail"
    ]


def test_load_cloud_sources_rejects_non_cloud() -> None:
    with pytest.raises(IngestError, match="Not cloud source"):
        load_cloud_sources(requested=("entra-signin",))


def test_ingest_cloud_dry_run_uses_repository_sample() -> None:
    results = ingest_cloud(dry_run=True)
    assert [result.source for result in results] == ["aws-cloudtrail"]
    assert results[0].read == 2
    assert results[0].unique == 2
    assert results[0].indices == ("edl-events-aws-cloudtrail-2026.11.01",)


def test_ingest_cloud_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_cloud(
        ingest_time=datetime(2026, 11, 22, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 1
    assert results[0].mode == "ingested"
    assert results[0].counts


def test_basename_handles_windows_and_posix_paths() -> None:
    from edl.ingest import _basename

    assert _basename("C:\\Windows\\System32\\PowerShell.EXE") == "powershell.exe"
    assert _basename("/usr/bin/bash") == "bash"
    assert _basename(None) is None
    assert _basename("") is None


M365_RAW = {
    "CreationTime": "2026-11-25T09:00:00Z",
    "Id": "00000000-0000-4000-8000-000000010101",
    "Operation": "New-InboxRule",
    "UserId": "analyst@example.test",
    "Workload": "Exchange",
    "RecordType": 2,
    "ClientIP": "203.0.113.10",
    "ObjectId": "analyst@example.test\\Inbox\\ForwardExternal",
    "ResultStatus": "Success",
    "Parameters": [
        {"Name": "Name", "Value": "Forward external invoices"},
        {"Name": "ForwardTo", "Value": "external@example.net"},
    ],
}

GITHUB_RAW = {
    "action": "org.add_member",
    "actor": "admin",
    "actor_ip": "203.0.113.10",
    "created_at": "2026-11-25T10:00:00Z",
    "id": "00000000-0000-4000-8000-000000020101",
    "org": "example-org",
    "repo": "example-org/lab",
    "permission": "admin",
    "user": "new-owner",
    "user_agent": "GitHub CLI",
}

EXCHANGE_MESSAGE_TRACE_RAW = {
    "MessageTraceId": "00000000-0000-4000-8000-000000030101",
    "MessageId": "<20261101094500.101@example.net>",
    "Date": "2026-11-01T09:45:00Z",
    "Event": "REDIRECT",
    "Source": "SMTP",
    "SenderAddress": "vendor@example.net",
    "RecipientAddress": "executive@example.test",
    "Subject": "Quarterly invoice redirect",
    "Status": "Delivered",
    "Directionality": "Outbound",
    "Action": "Redirect",
    "Detail": "Message redirected to external recipient collector@example.org",
    "Size": 48213,
    "FromIP": "203.0.113.31",
    "ToIP": "203.0.113.10",
    "RelatedRecipientAddress": "collector@example.org",
    "TenantId": "00000000-0000-4000-8000-000000009001",
    "Reference": "ref-redirect-external-101",
    "Index": 1,
}


def _saas_source(source_id: str) -> TelemetrySource:
    if source_id == "m365-audit":
        event_classes = ["audit", "mailbox"]
        event_time_field = "CreationTime"
        dedup_key = ["Id"]
        required_fields = ["CreationTime", "Id", "Operation", "UserId", "Workload", "RecordType"]
    elif source_id == "exchange-message-trace":
        event_classes = [
            "deliver",
            "forward",
            "redirect",
            "send",
            "receive",
            "fail",
            "defer",
            "expand",
            "transfer",
            "resolve",
            "other",
        ]
        event_time_field = "Date"
        dedup_key = ["MessageTraceId", "RecipientAddress", "Event", "Date"]
        required_fields = [
            "MessageTraceId",
            "MessageId",
            "SenderAddress",
            "RecipientAddress",
            "Date",
            "Event",
        ]
    else:
        event_classes = ["audit_log", "git", "authentication"]
        event_time_field = "created_at"
        dedup_key = ["id"]
        required_fields = ["action", "actor", "created_at", "id", "org", "repo"]
    return _source(
        source_id,
        event_classes=event_classes,
        event_time_field=event_time_field,
        dedup_key=dedup_key,
        required_fields=required_fields,
    )


@pytest.mark.parametrize(
    ("workload", "expected"),
    [
        ("Exchange", "mailbox"),
        ("SharePoint", "sharepoint"),
        ("OneDrive", "sharepoint"),
        ("MicrosoftTeams", "teams"),
        ("AzureActiveDirectory", "audit"),
    ],
)
def test_classify_m365_workload(workload: str, expected: str) -> None:
    assert classify_m365_audit({"Workload": workload}) == expected


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("git.push", "git"),
        ("user.login", "authentication"),
        ("user.failed_login", "authentication"),
        ("org.add_member", "audit_log"),
    ],
)
def test_classify_github_action(action: str, expected: str) -> None:
    assert classify_github_audit({"action": action}) == expected


def test_normalize_m365_audit_maps_mail_rule_fields() -> None:
    document = normalize_m365_audit(M365_RAW)
    assert document["event_id"] == M365_RAW["Id"]
    assert document["user"] == "analyst@example.test"
    assert document["action"] == "New-InboxRule"
    assert document["result"] == "success"
    assert document["workload"] == "Exchange"
    assert document["record_type"] == "2"
    assert document["rule_name"] == "Forward external invoices"
    assert document["forward_to"] == "external@example.net"
    assert document["forward_domain"] == "example.net"
    assert document["src_ip"] == "203.0.113.10"


def test_normalize_m365_audit_handles_parameter_mapping_and_failure() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": {"Name": "Rule", "RedirectTo": "redirect@example.net"},
            "ResultStatus": "Failed",
        }
    )
    assert document["rule_name"] == "Rule"
    assert document["forward_to"] == "redirect@example.net"
    assert document["result"] == "failure"


def test_normalize_github_audit_maps_organization_fields() -> None:
    document = normalize_github_audit(GITHUB_RAW)
    assert document["event_id"] == GITHUB_RAW["id"]
    assert document["user"] == "admin"
    assert document["action"] == "org.add_member"
    assert document["service"] == "github"
    assert document["organization"] == "example-org"
    assert document["repository"] == "example-org/lab"
    assert document["target_user"] == "new-owner"
    assert document["role"] == "admin"
    assert document["src_ip"] == "203.0.113.10"
    assert document["result"] == "success"


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        ("DELIVER", "deliver"),
        ("deliver", "deliver"),
        ("FORWARD", "forward"),
        ("REDIRECT", "redirect"),
        ("SEND", "send"),
        ("RECEIVE", "receive"),
        ("FAIL", "fail"),
        ("DEFER", "defer"),
        ("EXPAND", "expand"),
        ("TRANSFER", "transfer"),
        ("RESOLVE", "resolve"),
        ("UNKNOWN", "other"),
    ],
)
def test_classify_exchange_message_trace_event(event: str, expected: str) -> None:
    assert classify_exchange_message_trace({"Event": event}) == expected


def test_classify_exchange_message_trace_handles_missing_event() -> None:
    assert classify_exchange_message_trace({}) == "other"
    assert classify_exchange_message_trace({"Event": None}) == "other"
    assert classify_exchange_message_trace({"Event": 7}) == "other"


def test_normalize_exchange_message_trace_maps_external_redirect() -> None:
    document = normalize_exchange_message_trace(EXCHANGE_MESSAGE_TRACE_RAW)
    assert document["event_id"] == EXCHANGE_MESSAGE_TRACE_RAW["MessageTraceId"]
    assert document["message_trace_id"] == EXCHANGE_MESSAGE_TRACE_RAW["MessageTraceId"]
    assert document["message_id"] == EXCHANGE_MESSAGE_TRACE_RAW["MessageId"]
    assert document["sender"] == "vendor@example.net"
    assert document["recipient"] == "executive@example.test"
    assert document["recipients"] == ["executive@example.test"]
    assert document["recipient_domain"] == "example.test"
    assert document["recipient_domains"] == ["example.test"]
    assert document["external_recipient"] is False
    assert document["subject"] == "Quarterly invoice redirect"
    assert document["related_recipient"] == "collector@example.org"
    assert document["related_external"] is True
    assert document["mailbox"] == "executive@example.test"
    assert document["action"] == "REDIRECT"
    assert document["trace_event"] == "REDIRECT"
    assert document["trace_action"] == "Redirect"
    assert document["trace_detail"].startswith("Message redirected")
    assert document["delivery_status"] == "Delivered"
    assert document["directionality"] == "outbound"
    assert document["result"] == "success"
    assert document["size_bytes"] == 48213
    assert document["from_ip"] == "203.0.113.31"
    assert document["to_ip"] == "203.0.113.10"
    assert document["tenant_id"] == "00000000-0000-4000-8000-000000009001"
    assert document["source_component"] == "SMTP"
    assert document["trace_reference"] == "ref-redirect-external-101"
    assert document["trace_index"] == 1
    assert document["service"] == "exchange"


def test_normalize_exchange_message_trace_maps_internal_redirect() -> None:
    document = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "SenderAddress": "analyst@example.test",
            "RecipientAddress": "executive@example.test",
            "RelatedRecipientAddress": "manager@example.test",
            "Directionality": "Intra-org",
        }
    )
    assert document["related_recipient"] == "manager@example.test"
    assert document["related_external"] is False
    assert document["mailbox"] == "manager@example.test"
    assert document["directionality"] == "intra-org"


def test_normalize_exchange_message_trace_flags_external_recipient() -> None:
    document = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "Event": "SEND",
            "RecipientAddress": "recipient@example.net",
            "RelatedRecipientAddress": None,
        }
    )
    assert document["recipient_domains"] == ["example.net"]
    assert document["external_recipient"] is True
    assert "related_recipient" not in document
    assert "related_external" not in document
    assert "mailbox" not in document


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        ("DELIVER", "success"),
        ("FORWARD", "success"),
        ("REDIRECT", "success"),
        ("SEND", "success"),
        ("RECEIVE", "success"),
        ("EXPAND", "success"),
        ("TRANSFER", "success"),
        ("RESOLVE", "success"),
        ("FAIL", "failure"),
        ("DEFER", "pending"),
        ("UNKNOWN", None),
    ],
)
def test_normalize_exchange_message_trace_maps_result(event: str, expected: str | None) -> None:
    document = normalize_exchange_message_trace({**EXCHANGE_MESSAGE_TRACE_RAW, "Event": event})
    assert document.get("result") == expected


def test_normalize_exchange_message_trace_uses_original_client_ip_fallback() -> None:
    document = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "ClientIP": None,
            "OriginalClientIP": "198.51.100.12",
        }
    )
    assert document["client_ip"] == "198.51.100.12"


def test_normalize_exchange_message_trace_supports_recipient_lists() -> None:
    document = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "RecipientAddress": "analyst@example.test; partner@example.net",
            "RelatedRecipientAddress": ["manager@example.test", "vendor@example.org"],
        }
    )
    assert document["recipients"] == ["analyst@example.test", "partner@example.net"]
    assert document["recipient"] == "analyst@example.test"
    assert document["recipient_domains"] == ["example.net", "example.test"]
    assert document["external_recipient"] is True
    assert document["related_recipient"] == "manager@example.test"
    assert document["related_external"] is True
    assert document["mailbox"] == "manager@example.test"


def test_normalize_event_saas_classification() -> None:
    m365 = normalize_event(
        _saas_source("m365-audit"),
        M365_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert m365.event_class == "mailbox"

    github = normalize_event(
        _saas_source("github-audit"),
        GITHUB_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert github.event_class == "audit_log"

    exchange = normalize_event(
        _saas_source("exchange-message-trace"),
        EXCHANGE_MESSAGE_TRACE_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert exchange.event_class == "redirect"
    assert exchange.document["service"] == "exchange"


def test_load_saas_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_saas_sources()] == [
        "m365-audit",
        "github-audit",
        "exchange-message-trace",
        "m365-dlp",
        "servicenow-approval",
    ]
    assert [source.id for source in load_saas_sources(requested=("github-audit",))] == [
        "github-audit"
    ]
    assert [
        source.id
        for source in load_saas_sources(requested=("exchange-message-trace", "m365-audit"))
    ] == ["exchange-message-trace", "m365-audit"]


def test_load_saas_sources_rejects_non_saas() -> None:
    with pytest.raises(IngestError, match="Not saas source"):
        load_saas_sources(requested=("entra-signin",))


def test_ingest_saas_dry_run_uses_repository_samples() -> None:
    results = ingest_saas(dry_run=True)
    assert [result.source for result in results] == [
        "m365-audit",
        "github-audit",
        "exchange-message-trace",
        "m365-dlp",
        "servicenow-approval",
    ]
    assert [result.read for result in results] == [6, 2, 10, 7, 6]
    assert results[0].indices == (
        "edl-events-m365-audit-2026.11.01",
        "edl-events-m365-audit-2026.11.25",
    )
    assert results[1].indices == ("edl-events-github-audit-2026.11.25",)
    assert results[2].indices == (
        "edl-events-exchange-message-trace-2026.11.01",
        "edl-events-exchange-message-trace-2026.11.20",
    )
    assert results[3].indices == (
        "edl-events-m365-dlp-2026.11.01",
        "edl-events-m365-dlp-2026.11.02",
        "edl-events-m365-dlp-2026.11.03",
        "edl-events-m365-dlp-2026.11.04",
        "edl-events-m365-dlp-2026.11.05",
        "edl-events-m365-dlp-2026.11.06",
        "edl-events-m365-dlp-2026.11.20",
    )
    assert results[4].indices == (
        "edl-events-servicenow-approval-2026.11.20",
        "edl-events-servicenow-approval-2026.11.21",
        "edl-events-servicenow-approval-2026.11.22",
    )


def test_ingest_saas_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_saas(
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 5
    assert all(result.mode == "ingested" for result in results)
    assert all(result.counts for result in results)


def test_normalize_m365_audit_keeps_unknown_result_and_ignores_bad_parameters() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": ["bad", {"Name": "Name", "Value": "Rule"}],
            "ResultStatus": "Pending",
        }
    )
    assert document["result"] == "pending"
    assert document["rule_name"] == "Rule"


def test_normalize_m365_audit_supports_attachment_forwarding() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward attachments"},
                {"Name": "ForwardAsAttachmentTo", "Value": "archive@example.net"},
            ],
        }
    )
    assert document["forward_to"] == "archive@example.net"
    assert document["forward_domain"] == "example.net"


def test_normalize_github_audit_accepts_role_alias_and_lowercases() -> None:
    document = normalize_github_audit(
        {
            **GITHUB_RAW,
            "permission": "ADMIN",
        }
    )
    assert document["role"] == "admin"

    alias = normalize_github_audit({**GITHUB_RAW, "permission": None, "role": "Member"})
    assert alias["role"] == "member"


ZEEK_CONN = {
    "_path": "conn",
    "ts": 1795608000.0,
    "uid": "C1a2b3c4d5e6f7",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 49152,
    "id.resp_h": "198.51.100.25",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "orig_bytes": 812,
    "resp_bytes": 4021,
}

ZEEK_DNS = {
    **ZEEK_CONN,
    "_path": "dns",
    "uid": "C2b3c4d5e6f7a8",
    "id.orig_p": 53000,
    "id.resp_h": "203.0.113.53",
    "id.resp_p": 53,
    "proto": "udp",
    "query": "example.test",
    "qtype_name": "A",
}

ZEEK_HTTP = {
    **ZEEK_CONN,
    "_path": "http",
    "uid": "C3c4d5e6f7a8b9",
    "host": "intranet.example.test",
    "uri": "/status",
    "method": "GET",
    "status_code": 200,
    "user_agent": "Mozilla/5.0",
}

SURICATA_ALERT = {
    "timestamp": "2026-11-25T12:00:00Z",
    "flow_id": 900000000000001,
    "event_type": "alert",
    "src_ip": "10.0.0.5",
    "src_port": 49152,
    "dest_ip": "198.51.100.66",
    "dest_port": 443,
    "proto": "TCP",
    "app_proto": "http",
    "alert": {
        "signature": "ET MALWARE Example C2 Checkin",
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
    "flow": {"bytes_toserver": 620, "bytes_toclient": 1840},
}


def _network_source(source_id: str) -> TelemetrySource:
    zeek = source_id == "zeek"
    return _source(
        source_id,
        event_classes=(
            ["conn", "dns", "http", "ssl", "files", "other"]
            if zeek
            else ["alert", "flow", "dns", "http", "tls", "other"]
        ),
        event_time_field="ts" if zeek else "timestamp",
        dedup_key=["uid"] if zeek else ["flow_id", "event_type"],
        required_fields=(
            ["ts", "uid", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p", "proto", "_path"]
            if zeek
            else ["timestamp", "flow_id", "event_type", "src_ip", "dest_ip", "proto"]
        ),
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("conn", "conn"),
        ("dns", "dns"),
        ("http", "http"),
        ("ssl", "ssl"),
        ("files", "files"),
        ("weird", "other"),
    ],
)
def test_classify_zeek_maps_log_paths(path: str, expected: str) -> None:
    assert classify_zeek({"_path": path}) == expected


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        ("alert", "alert"),
        ("flow", "flow"),
        ("dns", "dns"),
        ("http", "http"),
        ("tls", "tls"),
        ("stats", "other"),
    ],
)
def test_classify_suricata_maps_event_types(event_type: str, expected: str) -> None:
    assert classify_suricata({"event_type": event_type}) == expected


def test_normalize_zeek_connection_and_dns() -> None:
    connection = normalize_zeek(ZEEK_CONN)
    assert connection["flow_id"] == ZEEK_CONN["uid"]
    assert connection["network_log"] == "conn"
    assert connection["network"] == {
        "source_ip": "10.0.0.5",
        "source_port": 49152,
        "destination_ip": "198.51.100.25",
        "destination_port": 443,
        "protocol": "tcp",
        "app_protocol": "ssl",
    }
    assert connection["bytes_sent"] == 812
    assert connection["bytes_received"] == 4021

    dns = normalize_zeek(ZEEK_DNS)
    assert dns["dns"] == {"query_name": "example.test", "query_type": "A", "query_length": 12}


def test_normalize_zeek_http_and_ssl() -> None:
    http = normalize_zeek(ZEEK_HTTP)
    assert http["http"] == {
        "host": "intranet.example.test",
        "uri": "/status",
        "method": "GET",
        "status": 200,
        "user_agent": "Mozilla/5.0",
    }
    assert http["user_agent"] == "Mozilla/5.0"

    ssl = normalize_zeek(
        {
            **ZEEK_CONN,
            "_path": "ssl",
            "server_name": "intranet.example.test",
            "version": "TLSv12",
            "cipher": "TLS_AES_256_GCM_SHA384",
        }
    )
    assert ssl["tls"] == {
        "sni": "intranet.example.test",
        "version": "TLSv12",
        "cipher": "TLS_AES_256_GCM_SHA384",
    }


def test_normalize_suricata_alert_and_dns() -> None:
    alert = normalize_suricata(SURICATA_ALERT)
    assert alert["flow_id"] == SURICATA_ALERT["flow_id"]
    assert alert["network_log"] == "alert"
    assert alert["network"] == {
        "source_ip": "10.0.0.5",
        "source_port": 49152,
        "destination_ip": "198.51.100.66",
        "destination_port": 443,
        "protocol": "TCP",
        "app_protocol": "http",
    }
    assert alert["alert"] == {
        "signature": "ET MALWARE Example C2 Checkin",
        "category": "A Network Trojan was detected",
        "severity": 1,
    }
    assert alert["bytes_sent"] == 620
    assert alert["bytes_received"] == 1840

    dns = normalize_suricata(
        {
            "timestamp": "2026-11-25T12:02:00Z",
            "flow_id": 900000000000003,
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "dest_ip": "203.0.113.53",
            "proto": "UDP",
            "dns": {"rrname": "example.test", "rrtype": "A"},
        }
    )
    assert dns["dns"] == {"query_name": "example.test", "query_type": "A", "query_length": 12}


def test_normalize_suricata_http_and_tls() -> None:
    http = normalize_suricata(
        {
            "timestamp": "2026-11-25T12:03:00Z",
            "flow_id": 900000000000004,
            "event_type": "http",
            "src_ip": "10.0.0.5",
            "dest_ip": "198.51.100.25",
            "proto": "TCP",
            "http": {
                "hostname": "intranet.example.test",
                "url": "/status",
                "http_method": "GET",
                "status": 200,
                "http_user_agent": "Mozilla/5.0",
            },
        }
    )
    assert http["http"] == {
        "host": "intranet.example.test",
        "uri": "/status",
        "method": "GET",
        "status": 200,
        "user_agent": "Mozilla/5.0",
    }
    assert http["user_agent"] == "Mozilla/5.0"

    tls = normalize_suricata(
        {
            "timestamp": "2026-11-25T12:04:00Z",
            "flow_id": 900000000000005,
            "event_type": "tls",
            "src_ip": "10.0.0.5",
            "dest_ip": "198.51.100.25",
            "proto": "TCP",
            "tls": {"sni": "intranet.example.test", "version": "TLS 1.2"},
        }
    )
    assert tls["tls"] == {"sni": "intranet.example.test", "version": "TLS 1.2"}


def test_normalize_event_accepts_epoch_seconds() -> None:
    event = normalize_event(
        _network_source("zeek"),
        ZEEK_CONN,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert event.event_class == "conn"
    assert event.event_time == datetime(2026, 11, 25, 12, 0, tzinfo=UTC)


def test_parse_timestamp_rejects_invalid_epoch_and_types() -> None:
    assert parse_timestamp(0, source="zeek", field="ts") == datetime(1970, 1, 1, tzinfo=UTC)
    with pytest.raises(IngestError):
        parse_timestamp(True, source="zeek", field="ts")
    with pytest.raises(IngestError):
        parse_timestamp("2026-11-25T12:00:00", source="zeek", field="ts")
    with pytest.raises(IngestError):
        parse_timestamp(float("inf"), source="zeek", field="ts")


def test_load_network_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_network_sources()] == ["zeek", "suricata"]
    assert [source.id for source in load_network_sources(requested=("suricata",))] == ["suricata"]


def test_load_network_sources_rejects_non_network() -> None:
    with pytest.raises(IngestError, match="Not network source"):
        load_network_sources(requested=("entra-signin",))


def test_ingest_network_dry_run_uses_repository_samples() -> None:
    results = ingest_network(dry_run=True)
    assert [result.source for result in results] == ["zeek", "suricata"]
    assert [result.read for result in results] == [4, 5]
    assert results[0].indices == ("edl-events-zeek-2026.11.25",)
    assert results[1].indices == ("edl-events-suricata-2026.11.25",)


def test_ingest_network_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_network(
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 2
    assert all(result.mode == "ingested" for result in results)
    assert all(result.counts for result in results)


KUBERNETES_RAW = {
    "auditID": "00000000-0000-4000-8000-000000010102",
    "requestReceivedTimestamp": "2026-11-25T14:05:00Z",
    "stage": "ResponseComplete",
    "verb": "create",
    "user": {"username": "system:serviceaccount:lab:deployer"},
    "objectRef": {"resource": "pods", "namespace": "lab", "name": "debug-pod"},
    "responseStatus": {"code": 201},
    "sourceIPs": ["10.0.0.7"],
    "requestObject": {
        "kind": "Pod",
        "spec": {
            "containers": [
                {
                    "name": "debug",
                    "image": "busybox:1.37",
                    "securityContext": {"privileged": True},
                }
            ]
        },
    },
}

FALCO_RAW = {
    "uuid": "00000000-0000-4000-8000-000000011101",
    "time": "2026-11-25T14:15:00Z",
    "rule": "Terminal shell in container",
    "priority": "Notice",
    "output_fields": {
        "container.name": "debug",
        "k8s.ns.name": "lab",
        "k8s.pod.name": "debug-pod",
        "proc.name": "bash",
        "proc.cmdline": "bash -i",
        "user.name": "root",
    },
}


def _kubernetes_source(source_id: str) -> TelemetrySource:
    audit = source_id == "kubernetes-audit"
    return _source(
        source_id,
        event_classes=["audit"] if audit else ["runtime_alert"],
        event_time_field="requestReceivedTimestamp" if audit else "time",
        dedup_key=["auditID"] if audit else ["uuid"],
        required_fields=(
            [
                "auditID",
                "requestReceivedTimestamp",
                "stage",
                "verb",
                "user",
                "objectRef",
                "responseStatus",
                "sourceIPs",
            ]
            if audit
            else ["time", "rule", "priority", "output_fields", "uuid"]
        ),
    )


def test_normalize_kubernetes_privileged_pod_creation() -> None:
    document = normalize_kubernetes_audit(KUBERNETES_RAW)
    assert document["event_id"] == KUBERNETES_RAW["auditID"]
    assert document["user"] == "system:serviceaccount:lab:deployer"
    assert document["action"] == "create"
    assert document["result"] == "success"
    assert document["resource_name"] == "pods"
    assert document["namespace"] == "lab"
    assert document["pod"] == "debug-pod"
    assert document["response_status"] == 201
    assert document["audit_stage"] == "ResponseComplete"
    assert document["privileged"] is True
    assert document["src_ip"] == "10.0.0.7"


def test_normalize_kubernetes_marks_failures_and_non_pod_requests() -> None:
    failed = normalize_kubernetes_audit(
        {
            **KUBERNETES_RAW,
            "verb": "delete",
            "objectRef": {"resource": "secrets", "namespace": "lab", "name": "db"},
            "responseStatus": {"code": 403},
            "requestObject": None,
        }
    )
    assert failed["result"] == "failure"
    assert failed["resource_name"] == "secrets"
    assert "pod" not in failed
    assert "privileged" not in failed

    unprivileged = normalize_kubernetes_audit(
        {
            **KUBERNETES_RAW,
            "requestObject": {
                "kind": "Pod",
                "spec": {
                    "initContainers": [{"name": "init", "securityContext": {"privileged": False}}],
                    "containers": [{"name": "app", "securityContext": {"privileged": False}}],
                },
            },
        }
    )
    assert unprivileged["privileged"] is False


def test_normalize_falco_runtime_alert() -> None:
    document = normalize_falco(FALCO_RAW)
    assert document["event_id"] == FALCO_RAW["uuid"]
    assert document["rule_name"] == "Terminal shell in container"
    assert document["priority"] == "Notice"
    assert document["namespace"] == "lab"
    assert document["pod"] == "debug-pod"
    assert document["container"] == "debug"
    assert document["user"] == "root"
    assert document["process"] == {"name": "bash", "command_line": "bash -i"}


def test_normalize_event_kubernetes_classification() -> None:
    audit = normalize_event(
        _kubernetes_source("kubernetes-audit"),
        KUBERNETES_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert audit.event_class == "audit"

    falco = normalize_event(
        _kubernetes_source("falco"),
        FALCO_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert falco.event_class == "runtime_alert"


def test_load_kubernetes_sources_defaults_and_filters() -> None:
    assert [source.id for source in load_kubernetes_sources()] == [
        "kubernetes-audit",
        "falco",
    ]
    assert [source.id for source in load_kubernetes_sources(requested=("falco",))] == ["falco"]


def test_load_kubernetes_sources_rejects_non_kubernetes() -> None:
    with pytest.raises(IngestError, match="Not kubernetes source"):
        load_kubernetes_sources(requested=("zeek",))


def test_ingest_kubernetes_dry_run_uses_repository_samples() -> None:
    results = ingest_kubernetes(dry_run=True)
    assert [result.source for result in results] == ["kubernetes-audit", "falco"]
    assert [result.read for result in results] == [3, 2]
    assert results[0].indices == ("edl-events-kubernetes-audit-2026.11.25",)
    assert results[1].indices == ("edl-events-falco-2026.11.25",)


def test_ingest_kubernetes_opens_client_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeClient()

    class FakeContext:
        def __enter__(self) -> FakeClient:
            return client

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr("edl.ingest.OpenSearchClient", lambda: FakeContext())
    results = ingest_kubernetes(
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
        index_prefix="edl-events-test",
    )
    assert len(results) == 2
    assert all(result.mode == "ingested" for result in results)
    assert all(result.counts for result in results)


def test_pod_privilege_helper_handles_incomplete_specs() -> None:
    missing_spec = normalize_kubernetes_audit(
        {**KUBERNETES_RAW, "requestObject": {"kind": "Pod", "spec": []}}
    )
    assert "privileged" not in missing_spec

    empty_spec = normalize_kubernetes_audit(
        {**KUBERNETES_RAW, "requestObject": {"kind": "Pod", "spec": {}}}
    )
    assert "privileged" not in empty_spec

    malformed_container = normalize_kubernetes_audit(
        {
            **KUBERNETES_RAW,
            "requestObject": {"kind": "Pod", "spec": {"containers": ["not-a-container"]}},
        }
    )
    assert malformed_container["privileged"] is False


def test_normalize_m365_audit_extracts_first_recipient_domain() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward external"},
                {
                    "Name": "ForwardTo",
                    "Value": "First@Example.Test; second@example.net",
                },
            ],
        }
    )
    assert document["forward_to"] == "First@Example.Test"
    assert document["forward_domain"] == "example.test"
    assert document["forward_domains"] == ["example.net", "example.test"]
    assert document["forward_external"] is True


def test_normalize_m365_audit_omits_domain_for_non_email_recipient() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward to team"},
                {"Name": "ForwardTo", "Value": "External Team"},
            ],
        }
    )
    assert document["forward_to"] == "External Team"
    assert "forward_domain" not in document


def test_normalize_m365_audit_tracks_all_forwarding_domains() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward multiple"},
                {
                    "Name": "ForwardTo",
                    "Value": "first@example.net; second@example.test",
                },
                {"Name": "RedirectTo", "Value": ["third@example.org"]},
            ],
        }
    )
    assert document["forward_to"] == "first@example.net"
    assert document["forward_domain"] == "example.net"
    assert document["forward_domains"] == ["example.net", "example.org", "example.test"]
    assert document["forward_external"] is True


def test_normalize_m365_audit_marks_internal_only_forwarding() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward internal"},
                {"Name": "ForwardTo", "Value": "team@example.test"},
            ],
        }
    )
    assert document["forward_domains"] == ["example.test"]
    assert document["forward_external"] is False


def test_normalize_m365_audit_reads_update_inbox_rules_properties() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "UpdateInboxRules",
            "Parameters": [{"Name": "Name", "Value": "Forward receipts"}],
            "OperationProperties": [
                {
                    "Name": "ForwardToRecipientsAction",
                    "Value": "receipts@example.net; archive@example.test",
                }
            ],
        }
    )
    assert document["rule_name"] == "Forward receipts"
    assert document["forward_to"] == "receipts@example.net"
    assert document["forward_domains"] == ["example.net", "example.test"]
    assert document["forward_external"] is True


def test_normalize_m365_audit_uses_configured_accepted_domains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = tmp_path / "tenant.yaml"
    tenant.write_text(
        "version: 1\naccepted_mail_domains:\n  - example.net\n  - example.org\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("edl.config.TENANT_CONFIG", tenant)
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward partner"},
                {"Name": "ForwardTo", "Value": "partner@example.net"},
            ],
        }
    )
    assert document["forward_external"] is False


def test_normalize_m365_audit_reads_recipient_mapping() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [{"Name": "Name", "Value": "Mapped recipient"}],
            "OperationProperties": [
                {
                    "Name": "ForwardToRecipientsAction",
                    "Value": {"Address": "mapped@example.net"},
                }
            ],
        }
    )
    assert document["forward_to"] == "mapped@example.net"
    assert document["forward_external"] is True


def test_normalize_m365_audit_ignores_unusable_recipient_values() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "No recipient"},
                {"Name": "ForwardTo", "Value": 123},
            ],
        }
    )
    assert "forward_to" not in document
    assert "forward_external" not in document


def test_normalize_m365_audit_maps_mailbox_permission_fields() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxPermission",
            "ObjectId": "shared-mailbox@example.test",
            "Parameters": [
                {"Name": "Identity", "Value": "shared-mailbox@example.test"},
                {"Name": "User", "Value": "analyst@example.test"},
                {"Name": "AccessRights", "Value": "FullAccess, SendAs"},
            ],
        }
    )
    assert document["mailbox"] == "shared-mailbox@example.test"
    assert document["delegate"] == "analyst@example.test"
    assert document["access_rights"] == ["FullAccess", "SendAs"]


def test_normalize_m365_audit_maps_mailbox_permission_list_rights() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxPermission",
            "Parameters": [
                {"Name": "Identity", "Value": "shared-mailbox@example.test"},
                {"Name": "Member", "Value": "analyst@example.test"},
                {"Name": "AccessRights", "Value": ["FullAccess", "SendAs"]},
            ],
        }
    )
    assert document["delegate"] == "analyst@example.test"
    assert document["access_rights"] == ["FullAccess", "SendAs"]


def test_normalize_m365_audit_maps_folder_permission_fields() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxFolderPermission",
            "ObjectId": "executive@example.test:\\Calendar",
            "Parameters": [
                {"Name": "Identity", "Value": "executive@example.test:\\Calendar"},
                {"Name": "User", "Value": "analyst@example.test"},
                {"Name": "AccessRights", "Value": "Editor"},
            ],
        }
    )
    assert document["mailbox"] == "executive@example.test"
    assert document["folder"] == "Calendar"
    assert document["delegate"] == "analyst@example.test"
    assert document["access_rights"] == ["Editor"]


def test_normalize_m365_audit_prefers_folder_name_parameter() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxFolderPermission",
            "Parameters": [
                {"Name": "Identity", "Value": "executive@example.test:\\Inbox"},
                {"Name": "FolderName", "Value": "Calendar"},
                {"Name": "User", "Value": "analyst@example.test"},
                {"Name": "AccessRights", "Value": "Owner"},
            ],
        }
    )
    assert document["mailbox"] == "executive@example.test"
    assert document["folder"] == "Calendar"
    assert document["access_rights"] == ["Owner"]


def test_normalize_m365_audit_maps_distribution_group_member() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-DistributionGroupMember",
            "ObjectId": "finance-team@example.test",
            "Parameters": [
                {"Name": "Identity", "Value": "finance-team@example.test"},
                {"Name": "Member", "Value": "analyst@example.test"},
            ],
        }
    )
    assert document["group"] == "finance-team@example.test"
    assert document["group_member"] == "analyst@example.test"
    assert "mailbox" not in document


def test_normalize_m365_audit_marks_self_delegation() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxPermission",
            "Parameters": [
                {"Name": "Identity", "Value": "executive@example.test"},
                {"Name": "User", "Value": "analyst@example.test"},
                {"Name": "AccessRights", "Value": "FullAccess"},
            ],
        }
    )
    assert document["self_delegation"] is True

    other = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "Add-MailboxPermission",
            "Parameters": [
                {"Name": "Identity", "Value": "executive@example.test"},
                {"Name": "User", "Value": "contractor@example.test"},
                {"Name": "AccessRights", "Value": "FullAccess"},
            ],
        }
    )
    assert other["self_delegation"] is False


def test_normalize_m365_audit_maps_mail_access_target() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "MailItemsAccessed",
            "ObjectId": "executive@example.test\\Inbox",
            "Parameters": [{"Name": "MailAccessType", "Value": "Bind"}],
        }
    )
    assert document["mailbox"] == "executive@example.test"
    assert document["folder"] == "Inbox"


def test_classify_m365_operation_overrides_workload() -> None:
    assert (
        classify_m365_audit({"Workload": "Exchange", "Operation": "Add-MailboxPermission"})
        == "mailbox_permission"
    )
    assert (
        classify_m365_audit({"Workload": "Exchange", "Operation": "Add-MailboxFolderPermission"})
        == "mailbox_permission"
    )
    assert (
        classify_m365_audit({"Workload": "Exchange", "Operation": "Add-UnifiedGroupLinks"})
        == "mailbox_permission"
    )
    assert (
        classify_m365_audit({"Workload": "Exchange", "Operation": "MailItemsAccessed"})
        == "mail_access"
    )
    assert classify_m365_audit({"Workload": "Exchange", "Operation": "New-InboxRule"}) == "mailbox"


def test_normalize_m365_audit_maps_inbox_rule_mailbox() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Operation": "New-InboxRule",
            "ObjectId": "executive@example.test\\Inbox\\Forward invoices",
        }
    )
    assert document["mailbox"] == "executive@example.test"
    assert document["folder"] == "Inbox\\Forward invoices"


def test_normalize_m365_audit_sets_delivery_recipient() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward invoices"},
                {"Name": "ForwardTo", "Value": "Collector@Example.ORG"},
            ],
        }
    )
    assert document["delivery_recipient"] == "collector@example.org"


def test_normalize_exchange_message_trace_sets_delivery_recipient() -> None:
    delivered = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "Event": "DELIVER",
            "RecipientAddress": "Collector@Example.ORG",
            "RelatedRecipientAddress": "executive@example.test",
        }
    )
    assert delivered["delivery_recipient"] == "collector@example.org"

    redirected = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "Event": "REDIRECT",
            "RecipientAddress": "executive@example.test",
            "RelatedRecipientAddress": "Collector@Example.ORG",
        }
    )
    assert redirected["delivery_recipient"] == "collector@example.org"


def test_normalize_m365_audit_sets_all_delivery_recipients() -> None:
    document = normalize_m365_audit(
        {
            **M365_RAW,
            "Parameters": [
                {"Name": "Name", "Value": "Forward invoices"},
                {
                    "Name": "ForwardTo",
                    "Value": "Collector@Example.ORG; second@example.net",
                },
            ],
        }
    )
    assert document["delivery_recipient"] == "collector@example.org"
    assert document["delivery_recipients"] == ["collector@example.org", "second@example.net"]


def test_normalize_exchange_message_trace_sets_all_external_delivery_recipients() -> None:
    document = normalize_exchange_message_trace(
        {
            **EXCHANGE_MESSAGE_TRACE_RAW,
            "Event": "DELIVER",
            "RecipientAddress": "Collector@Example.ORG; second@example.net",
            "RelatedRecipientAddress": "executive@example.test",
        }
    )
    assert document["delivery_recipient"] == "collector@example.org"
    assert document["delivery_recipients"] == ["collector@example.org", "second@example.net"]


M365_DLP_RAW = {
    "AlertId": "00000000-0000-4000-8000-000000040101",
    "CreationTime": "2026-11-01T09:47:00Z",
    "PolicyName": "External financial data",
    "Severity": "High",
    "Status": "Active",
    "User": "analyst@example.test",
    "Workload": "Exchange",
    "Recipient": "collector@example.org",
    "Subject": "Quarterly invoice redirect",
    "MessageId": "<20261101094600.102@example.org>",
    "DetectionMethod": "DLP",
    "Action": "Block",
}


def test_normalize_m365_dlp_maps_alert_fields() -> None:
    document = normalize_m365_dlp(M365_DLP_RAW)
    assert document["event_id"] == M365_DLP_RAW["AlertId"]
    assert document["user"] == "analyst@example.test"
    assert document["action"] == "External financial data"
    assert document["status"] == "active"
    assert document["severity"] == "high"
    assert document["policy_name"] == "External financial data"
    assert document["recipient"] == "collector@example.org"
    assert document["delivery_recipient"] == "collector@example.org"
    assert document["subject"] == "Quarterly invoice redirect"
    assert document["message_id"] == "<20261101094600.102@example.org>"
    assert document["workload"] == "Exchange"
    assert document["detection_method"] == "DLP"
    assert document["dlp_action"] == "Block"
    assert document["service"] == "purview-dlp"


def test_normalize_m365_dlp_handles_missing_status_and_severity() -> None:
    document = normalize_m365_dlp({**M365_DLP_RAW, "Status": None, "Severity": None})
    assert "status" not in document
    assert "severity" not in document


def test_normalize_m365_dlp_lowercases_message_id() -> None:
    document = normalize_m365_dlp({**M365_DLP_RAW, "MessageId": "<20261101094600.102@Example.ORG>"})
    assert document["message_id"] == "<20261101094600.102@example.org>"


def test_normalize_exchange_message_trace_lowercases_message_id() -> None:
    document = normalize_exchange_message_trace(
        {**EXCHANGE_MESSAGE_TRACE_RAW, "MessageId": "<20261101094500.101@Example.NET>"}
    )
    assert document["message_id"] == "<20261101094500.101@example.net>"


SERVICENOW_APPROVAL_RAW = {
    "sys_id": "00000000-0000-4000-8000-000000070101",
    "number": "REQ0007001",
    "sys_updated_on": "2026-11-20T14:05:00Z",
    "state": "Closed",
    "approval": "Denied",
    "requested_for": "Analyst@Example.TEST",
    "requested_by": "analyst@example.test",
    "approver": "data-owner@example.test",
    "recipient": "Partner@Example.ORG",
    "message_id": "<20261120144000.701@Example.ORG>",
    "short_description": "Customer dataset export",
}


def test_normalize_servicenow_approval_maps_decision_fields() -> None:
    document = normalize_servicenow_approval(SERVICENOW_APPROVAL_RAW)
    assert document["event_id"] == SERVICENOW_APPROVAL_RAW["sys_id"]
    assert document["request_number"] == "REQ0007001"
    assert document["status"] == "closed"
    assert document["decision"] == "denied"
    assert document["mailbox"] == "analyst@example.test"
    assert document["requested_by"] == "analyst@example.test"
    assert document["approver"] == "data-owner@example.test"
    assert document["recipient"] == "Partner@Example.ORG"
    assert document["delivery_recipient"] == "partner@example.org"
    assert document["message_id"] == "<20261120144000.701@example.org>"
    assert document["subject"] == "Customer dataset export"
    assert document["service"] == "servicenow-approval"


def test_normalize_servicenow_approval_handles_missing_optional_fields() -> None:
    document = normalize_servicenow_approval(
        {**SERVICENOW_APPROVAL_RAW, "approver": None, "requested_by": None}
    )
    assert "approver" not in document
    assert "requested_by" not in document


def test_normalize_event_servicenow_approval_is_approval_class() -> None:
    source = _source(
        "servicenow-approval",
        event_classes=["approval"],
        event_time_field="sys_updated_on",
        dedup_key=["sys_id"],
        required_fields=["sys_id", "sys_updated_on", "state", "approval"],
    )
    event = normalize_event(
        source,
        SERVICENOW_APPROVAL_RAW,
        ingest_time=datetime(2026, 11, 25, tzinfo=UTC),
    )
    assert event.event_class == "approval"
    assert event.document["decision"] == "denied"
