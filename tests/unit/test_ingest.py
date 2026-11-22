from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from edl.errors import IngestError
from edl.ingest import (
    CanonicalEvent,
    dedup_fingerprint,
    deduplicate_events,
    format_timestamp,
    index_name,
    ingest_identity,
    ingest_source,
    load_dataset,
    load_identity_sources,
    normalize_dataset,
    normalize_entra_audit,
    normalize_entra_signin,
    normalize_event,
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
    assert all(result.read == 2 for result in results)
    assert all(result.unique == 2 for result in results)
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
