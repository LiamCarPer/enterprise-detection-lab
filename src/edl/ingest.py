"""Normalize telemetry and ingest it into OpenSearch."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from . import config
from .errors import IngestError
from .telemetry import TelemetrySource, load_sources
from .utils import read_json, sha256_file

Normalizer = Callable[[Mapping[str, Any]], dict[str, Any]]
Classifier = Callable[[Mapping[str, Any]], str]

IDENTITY_SOURCES: tuple[str, ...] = ("entra-signin", "entra-audit")
ENDPOINT_SOURCES: tuple[str, ...] = ("sysmon", "windows-security")
CLOUD_SOURCES: tuple[str, ...] = ("aws-cloudtrail",)
DOMAIN_SOURCES: dict[str, tuple[str, ...]] = {
    "identity": IDENTITY_SOURCES,
    "endpoint": ENDPOINT_SOURCES,
    "cloud": CLOUD_SOURCES,
}


@dataclass(frozen=True)
class CanonicalEvent:
    """One validated event ready to be written to OpenSearch."""

    source: str
    event_class: str
    event_time: datetime
    ingest_time: datetime
    document: dict[str, Any]
    dedup_id: str


@dataclass(frozen=True)
class IngestResult:
    """Outcome of one source ingest."""

    source: str
    dataset: Path
    read: int
    unique: int
    duplicates: int
    indices: tuple[str, ...]
    written: int
    counts: dict[str, int]
    dry_run: bool

    @property
    def mode(self) -> str:
        return "dry-run" if self.dry_run else "ingested"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dataset": str(self.dataset),
            "read": self.read,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "indices": list(self.indices),
            "written": self.written,
            "counts": self.counts,
            "dry_run": self.dry_run,
            "mode": self.mode,
        }


def parse_timestamp(value: Any, *, source: str, field: str) -> datetime:
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value:
        raise IngestError(f"{source}: {field} must be a non-empty ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IngestError(f"{source}: invalid {field}: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise IngestError(f"{source}: naive {field} is not allowed: {value!r}")
    return parsed.astimezone(UTC)


def format_timestamp(value: datetime) -> str:
    """Render a timestamp as UTC ISO 8601 with a Z suffix."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _lookup(data: Mapping[str, Any], dotted: str) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _compact(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if _present(value)}


def _meaningful(value: Any) -> Any:
    """Drop placeholders used by Windows event exports."""
    if value is None or value == "" or value == "-":
        return None
    return value


def _basename(value: Any) -> str | None:
    """Return a lowercase executable basename for either path separator."""
    if not isinstance(value, str) or not value:
        return None
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _event_id(raw: Mapping[str, Any]) -> int | None:
    value = raw.get("EventID")
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


SYSMON_EVENT_CLASSES: dict[int, str] = {
    1: "process_creation",
    3: "network_connection",
    10: "process_access",
    11: "file_create",
    12: "registry_set",
    13: "registry_set",
    14: "registry_set",
    22: "dns_query",
}

WINDOWS_AUTHENTICATION_EVENT_IDS: frozenset[int] = frozenset(
    {4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4776}
)
WINDOWS_ACCOUNT_MANAGEMENT_EVENT_IDS: frozenset[int] = frozenset(
    {
        4720,
        4722,
        4723,
        4724,
        4725,
        4726,
        4728,
        4732,
        4738,
        4740,
        4756,
        4767,
    }
)

WINDOWS_ACTIONS: dict[int, str] = {
    4624: "logon",
    4625: "logon_failure",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "explicit_credential_logon",
    4672: "special_privileges_assigned",
    4720: "user_created",
    4722: "user_enabled",
    4723: "password_change_attempt",
    4724: "password_reset",
    4725: "user_disabled",
    4726: "user_deleted",
    4728: "member_added_to_global_group",
    4732: "member_added_to_local_group",
    4738: "user_changed",
    4740: "user_locked",
    4756: "member_added_to_universal_group",
    4767: "user_unlocked",
    4768: "kerberos_tgt_requested",
    4769: "kerberos_service_ticket_requested",
    4776: "ntlm_authentication",
}


def classify_sysmon(raw: Mapping[str, Any]) -> str:
    """Map a Sysmon EventID to a declared event class."""
    event_id = _event_id(raw)
    if event_id is None:
        return "other"
    return SYSMON_EVENT_CLASSES.get(event_id, "other")


def classify_windows_security(raw: Mapping[str, Any]) -> str:
    """Map a Windows Security EventID to a declared event class."""
    event_id = _event_id(raw)
    if event_id in WINDOWS_AUTHENTICATION_EVENT_IDS:
        return "authentication"
    if event_id in WINDOWS_ACCOUNT_MANAGEMENT_EVENT_IDS:
        return "account_management"
    return "other"


def normalize_entra_signin(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Entra sign-in fields to the canonical identity shape."""
    document: dict[str, Any] = {
        "action": "sign_in",
        "event_id": raw.get("id"),
        "user": raw.get("userPrincipalName"),
        "src_ip": raw.get("ipAddress"),
        "app": raw.get("appDisplayName"),
        "result": raw.get("status"),
        "auth_requirement": raw.get("authenticationRequirement"),
        "is_interactive": raw.get("isInteractive"),
        "conditional_access_status": raw.get("conditionalAccessStatus"),
        "risk_level": raw.get("riskLevelDuringSignIn"),
    }

    device = raw.get("deviceDetail")
    if isinstance(device, Mapping):
        detail = _compact(
            {
                "os": device.get("operatingSystem"),
                "browser": device.get("browser"),
            }
        )
        if detail:
            document["device"] = detail
    return _compact(document)


def normalize_entra_audit(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Entra audit fields to the canonical identity shape."""
    user: Any = None
    app: Any = None
    src_ip: Any = None

    initiated_by = raw.get("initiatedBy")
    if isinstance(initiated_by, Mapping):
        user_data = initiated_by.get("user")
        if isinstance(user_data, Mapping):
            user = user_data.get("userPrincipalName") or user_data.get("displayName")
            src_ip = user_data.get("ipAddress")
        app_data = initiated_by.get("app")
        if isinstance(app_data, Mapping):
            app = app_data.get("displayName")
            if user is None:
                user = app

    document: dict[str, Any] = {
        "action": raw.get("operationName"),
        "event_id": raw.get("id"),
        "user": user,
        "app": app,
        "src_ip": src_ip,
        "result": raw.get("result"),
    }

    targets = raw.get("targetResources")
    if isinstance(targets, list) and targets:
        first = targets[0]
        if isinstance(first, Mapping):
            resource = _compact(
                {
                    "name": first.get("displayName"),
                    "type": first.get("type"),
                }
            )
            resource["count"] = len(targets)
            document["resource"] = resource
    return _compact(document)


NORMALIZERS: dict[str, Normalizer] = {
    "entra-signin": normalize_entra_signin,
    "entra-audit": normalize_entra_audit,
}


def normalize_sysmon(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Sysmon fields to the canonical endpoint shape."""
    document: dict[str, Any] = {
        "host": raw.get("Computer"),
        "user": raw.get("User"),
        "event_code": _event_id(raw),
    }

    process = _compact(
        {
            "name": _basename(raw.get("Image")),
            "image": raw.get("Image"),
            "command_line": raw.get("CommandLine"),
            "guid": raw.get("ProcessGuid"),
            "id": raw.get("ProcessId"),
            "parent_name": _basename(raw.get("ParentImage")),
            "parent_image": raw.get("ParentImage"),
            "parent_command_line": raw.get("ParentCommandLine"),
        }
    )
    if process:
        document["process"] = process

    network = _compact(
        {
            "source_ip": raw.get("SourceIp"),
            "source_port": raw.get("SourcePort"),
            "destination_ip": raw.get("DestinationIp"),
            "destination_port": raw.get("DestinationPort"),
            "protocol": raw.get("Protocol"),
        }
    )
    if network:
        document["network"] = network

    file_fields = _compact({"target_filename": raw.get("TargetFilename")})
    if file_fields:
        document["file"] = file_fields

    registry = _compact(
        {
            "target_object": raw.get("TargetObject"),
            "details": raw.get("Details"),
        }
    )
    if registry:
        document["registry"] = registry

    dns = _compact(
        {
            "query_name": raw.get("QueryName"),
            "query_results": raw.get("QueryResults"),
        }
    )
    if dns:
        document["dns"] = dns

    return _compact(document)


def normalize_windows_security(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map Windows Security fields to the canonical endpoint shape."""
    event_id = _event_id(raw)
    if event_id == 4624:
        result = "success"
    elif event_id == 4625:
        result = "failure"
    else:
        result = None

    document: dict[str, Any] = {
        "host": raw.get("Computer"),
        "user": _meaningful(raw.get("TargetUserName")),
        "event_code": event_id,
        "action": WINDOWS_ACTIONS.get(event_id) if event_id is not None else None,
        "result": result,
        "src_ip": _meaningful(raw.get("IpAddress")),
        "logon_type": raw.get("LogonType"),
        "status": _meaningful(raw.get("Status")),
        "subject_user": _meaningful(raw.get("SubjectUserName")),
        "service_name": _meaningful(raw.get("ServiceName")),
        "task_name": _meaningful(raw.get("TaskName")),
    }
    return _compact(document)


def normalize_aws_cloudtrail(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Map AWS CloudTrail fields to the canonical cloud shape."""
    identity = raw.get("userIdentity")
    identity_type: Any = None
    identity_arn: Any = None
    if isinstance(identity, Mapping):
        identity_type = identity.get("type")
        identity_arn = identity.get("arn") or identity.get("principalId")

    error_code = _meaningful(raw.get("errorCode"))
    document: dict[str, Any] = {
        "user": identity_arn,
        "src_ip": _meaningful(raw.get("sourceIPAddress")),
        "action": raw.get("eventName"),
        "result": "failure" if error_code else "success",
        "service": raw.get("eventSource"),
        "account": raw.get("recipientAccountId"),
        "region": raw.get("awsRegion"),
        "event_id": raw.get("eventID"),
        "identity_type": identity_type,
        "identity_arn": identity_arn,
        "error_code": error_code,
        "user_agent": _meaningful(raw.get("userAgent")),
    }
    return _compact(document)


NORMALIZERS.update(
    {
        "sysmon": normalize_sysmon,
        "windows-security": normalize_windows_security,
        "aws-cloudtrail": normalize_aws_cloudtrail,
    }
)

CLASSIFIERS: dict[str, Classifier] = {
    "sysmon": classify_sysmon,
    "windows-security": classify_windows_security,
}


def _required_fields(source: TelemetrySource) -> list[str]:
    values = source.data.get("required_fields")
    if not isinstance(values, list):
        return []
    return [str(value) for value in values]


def dedup_fingerprint(
    source_id: str,
    key_names: Sequence[str],
    raw: Mapping[str, Any],
) -> tuple[str, dict[str, Any], str]:
    """Return a deterministic document ID, key values, and key origin."""
    key_values: dict[str, Any] = {}
    for name in key_names:
        value = _lookup(raw, name)
        if not _present(value):
            break
        key_values[name] = value

    if len(key_values) == len(key_names) and key_values:
        material = {"source": source_id, "key": key_values}
        origin = "declared"
    else:
        key_values = {}
        material = {"source": source_id, "raw": raw}
        origin = "hash"

    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest(), key_values, origin


def normalize_event(
    source: TelemetrySource,
    raw: Mapping[str, Any],
    *,
    ingest_time: datetime,
) -> CanonicalEvent:
    """Validate and normalize one event against its source contract."""
    if not isinstance(raw, Mapping):
        raise IngestError(f"{source.id}: event must be an object")

    normalizer = NORMALIZERS.get(source.id)
    if normalizer is None:
        raise IngestError(f"No normalizer registered for source {source.id!r}")

    missing = [field for field in _required_fields(source) if not _present(_lookup(raw, field))]
    if missing:
        raise IngestError(f"{source.id}: missing required field(s): {', '.join(missing)}")

    event_time_field = str(source.data.get("event_time_field", ""))
    if not event_time_field:
        raise IngestError(f"{source.id}: event_time_field is not declared")
    event_time = parse_timestamp(
        raw.get(event_time_field),
        source=source.id,
        field=event_time_field,
    )

    key_names = source.data.get("dedup_key")
    if not isinstance(key_names, list) or not key_names:
        raise IngestError(f"{source.id}: dedup_key is not declared")
    dedup_id, dedup_key, dedup_origin = dedup_fingerprint(
        source.id,
        [str(name) for name in key_names],
        raw,
    )

    event_classes = source.data.get("event_classes")
    if not isinstance(event_classes, list) or not event_classes:
        raise IngestError(f"{source.id}: event_classes is not declared")
    declared_classes = [str(item) for item in event_classes]
    classifier = CLASSIFIERS.get(source.id)
    event_class = classifier(raw) if classifier is not None else declared_classes[0]
    if event_class not in declared_classes:
        raise IngestError(
            f"{source.id}: classifier returned undeclared event class {event_class!r}"
        )

    document: dict[str, Any] = {
        "@timestamp": format_timestamp(event_time),
        "event_time": format_timestamp(event_time),
        "ingest_time": format_timestamp(ingest_time),
        "source": source.id,
        "event_class": event_class,
        "schema_version": str(source.data.get("schema_version", "")),
        "dedup_key": dedup_key,
        "dedup_origin": dedup_origin,
        "raw": dict(raw),
    }
    document.update(normalizer(raw))

    return CanonicalEvent(
        source=source.id,
        event_class=event_class,
        event_time=event_time,
        ingest_time=ingest_time,
        document=document,
        dedup_id=dedup_id,
    )


def normalize_dataset(
    source: TelemetrySource,
    events: Sequence[Any],
    *,
    ingest_time: datetime,
) -> list[CanonicalEvent]:
    """Normalize every event, reporting the first invalid dataset item."""
    normalized: list[CanonicalEvent] = []
    for position, raw in enumerate(events, start=1):
        try:
            normalized.append(normalize_event(source, raw, ingest_time=ingest_time))
        except IngestError as exc:
            raise IngestError(f"{exc} (dataset item {position})") from exc
    return normalized


def deduplicate_events(
    events: Sequence[CanonicalEvent],
) -> tuple[list[CanonicalEvent], int]:
    """Collapse deterministic IDs, keeping the first occurrence."""
    seen: set[str] = set()
    unique: list[CanonicalEvent] = []
    for event in events:
        if event.dedup_id in seen:
            continue
        seen.add(event.dedup_id)
        unique.append(event)
    return unique, len(events) - len(unique)


def index_name(prefix: str, source_id: str, event_time: datetime) -> str:
    """Return the event-time-based daily index name."""
    utc_time = event_time.astimezone(UTC)
    return f"{prefix}-{source_id}-{utc_time:%Y.%m.%d}"


def load_dataset(source: TelemetrySource, root: Path) -> tuple[Path, list[Any]]:
    """Load, hash-check, and shape-check a source's sample dataset."""
    sample = source.data.get("sample_data")
    if not isinstance(sample, Mapping):
        raise IngestError(f"{source.id}: no sample_data contract")

    path_value = sample.get("path")
    if not isinstance(path_value, str) or not path_value:
        raise IngestError(f"{source.id}: sample_data.path is empty")
    path = root / path_value
    if not path.is_file():
        raise IngestError(f"{source.id}: sample dataset not found: {path}")

    expected_hash = sample.get("sha256")
    if isinstance(expected_hash, str) and sha256_file(path) != expected_hash.lower():
        raise IngestError(f"{source.id}: sample dataset hash does not match: {path}")

    try:
        data = read_json(path)
    except (OSError, ValueError) as exc:
        raise IngestError(f"{source.id}: cannot read sample dataset: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise IngestError(f"{source.id}: sample dataset must be a non-empty JSON array")
    return path, data


class OpenSearchClient:
    """Small OpenSearch client with bulk, count, and cleanup helpers."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.Client(
            base_url=(base_url or config.OPENSEARCH_URL).rstrip("/"),
            timeout=timeout,
            transport=transport,
        )

    def __enter__(self) -> OpenSearchClient:
        return self

    def __exit__(self, *_: object) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    def bulk(
        self,
        index: str,
        actions: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        refresh: bool,
    ) -> None:
        if not actions:
            return

        lines: list[str] = []
        for doc_id, document in actions:
            lines.append(json.dumps({"index": {"_id": doc_id}}, separators=(",", ":")))
            lines.append(
                json.dumps(
                    dict(document),
                    sort_keys=True,
                    separators=(",", ":"),
                    default=str,
                )
            )
        body = "\n".join(lines) + "\n"

        try:
            response = self._client.post(
                f"/{index}/_bulk",
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/x-ndjson"},
                params={"refresh": "true" if refresh else "false"},
            )
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch bulk failed with HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch bulk returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise IngestError("OpenSearch bulk returned a non-object response")
        if not payload.get("errors"):
            return

        failures: list[dict[str, Any]] = []
        items = payload.get("items")
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                operation = next(iter(item.values()), None)
                if isinstance(operation, Mapping) and operation.get("error"):
                    failures.append(dict(operation))
        detail = json.dumps(failures[0], sort_keys=True)[:500] if failures else "unknown bulk error"
        raise IngestError(f"OpenSearch rejected documents: {detail}")

    def search(self, index: str, body: Mapping[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(f"/{index}/_search", json=dict(body))
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch search failed with HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch search returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise IngestError("OpenSearch search returned a non-object response")
        return dict(payload)

    def count(self, index: str) -> int:
        try:
            response = self._client.get(f"/{index}/_count")
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code == 404:
            return 0
        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch count failed with HTTP {response.status_code}: {response.text[:300]}"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise IngestError("OpenSearch count returned a non-JSON response") from exc
        if not isinstance(payload, Mapping) or not isinstance(payload.get("count"), int):
            raise IngestError("OpenSearch count response did not contain an integer count")
        return int(payload["count"])

    def delete_matching(self, index_pattern: str) -> None:
        try:
            response = self._client.delete(f"/{index_pattern}")
        except httpx.HTTPError as exc:
            raise IngestError(f"Could not reach OpenSearch: {exc}") from exc

        if response.status_code == 404:
            return
        if response.status_code >= 300:
            raise IngestError(
                f"OpenSearch delete failed with HTTP {response.status_code}: {response.text[:300]}"
            )


def write_events(
    client: OpenSearchClient,
    events: Sequence[CanonicalEvent],
    *,
    index_prefix: str,
    refresh: bool,
    batch_size: int,
) -> tuple[int, dict[str, int]]:
    """Write events in batches and return written count and index counts."""
    if batch_size < 1:
        raise IngestError("batch_size must be at least 1")

    grouped: dict[str, list[CanonicalEvent]] = {}
    for event in events:
        target = index_name(index_prefix, event.source, event.event_time)
        grouped.setdefault(target, []).append(event)

    written = 0
    for target in sorted(grouped):
        batch = grouped[target]
        for start in range(0, len(batch), batch_size):
            chunk = batch[start : start + batch_size]
            client.bulk(
                target,
                [(event.dedup_id, event.document) for event in chunk],
                refresh=refresh,
            )
            written += len(chunk)

    counts = {target: client.count(target) for target in sorted(grouped)} if refresh else {}
    return written, counts


def ingest_source(
    source: TelemetrySource,
    root: Path = config.ROOT,
    *,
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> IngestResult:
    """Normalize and ingest one source's sample dataset."""
    dataset, raw_events = load_dataset(source, root)
    event_time = ingest_time or datetime.now(UTC)
    normalized = normalize_dataset(source, raw_events, ingest_time=event_time)
    unique, duplicates = deduplicate_events(normalized)
    indices = tuple(
        sorted({index_name(index_prefix, event.source, event.event_time) for event in unique})
    )

    if dry_run:
        return IngestResult(
            source=source.id,
            dataset=dataset,
            read=len(normalized),
            unique=len(unique),
            duplicates=duplicates,
            indices=indices,
            written=0,
            counts={},
            dry_run=True,
        )

    if client is None:
        with OpenSearchClient() as active:
            written, counts = write_events(
                active,
                unique,
                index_prefix=index_prefix,
                refresh=refresh,
                batch_size=batch_size,
            )
    else:
        written, counts = write_events(
            client,
            unique,
            index_prefix=index_prefix,
            refresh=refresh,
            batch_size=batch_size,
        )

    return IngestResult(
        source=source.id,
        dataset=dataset,
        read=len(normalized),
        unique=len(unique),
        duplicates=duplicates,
        indices=indices,
        written=written,
        counts=counts,
        dry_run=False,
    )


def load_domain_sources(
    domain: str,
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected source contracts for a domain."""
    supported = DOMAIN_SOURCES.get(domain)
    if supported is None:
        raise IngestError(f"Unknown ingest domain: {domain}")

    sources = {source.id: source for source in load_sources(root)}
    source_ids = list(dict.fromkeys(requested)) or list(supported)

    unknown = [source_id for source_id in source_ids if source_id not in sources]
    if unknown:
        raise IngestError(f"Unknown telemetry source(s): {', '.join(unknown)}")

    unsupported = [source_id for source_id in source_ids if source_id not in supported]
    if unsupported:
        raise IngestError(f"Not {domain} source(s): {', '.join(unsupported)}")

    return [sources[source_id] for source_id in source_ids]


def load_identity_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected identity source contracts."""
    return load_domain_sources("identity", root, requested)


def load_endpoint_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected endpoint source contracts."""
    return load_domain_sources("endpoint", root, requested)


def load_cloud_sources(
    root: Path = config.ROOT,
    requested: Sequence[str] = (),
) -> list[TelemetrySource]:
    """Load and validate the selected cloud source contracts."""
    return load_domain_sources("cloud", root, requested)


def ingest_domain(
    domain: str,
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected sources for one telemetry domain."""
    selected = load_domain_sources(domain, root, sources)

    def run(active: OpenSearchClient | None) -> list[IngestResult]:
        return [
            ingest_source(
                source,
                root,
                client=active,
                ingest_time=ingest_time,
                index_prefix=index_prefix,
                refresh=refresh,
                batch_size=batch_size,
                dry_run=dry_run,
            )
            for source in selected
        ]

    if dry_run or client is not None:
        return run(client)
    with OpenSearchClient() as active:
        return run(active)


def ingest_identity(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected identity sources into OpenSearch."""
    return ingest_domain(
        "identity",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_endpoint(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected endpoint sources into OpenSearch."""
    return ingest_domain(
        "endpoint",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def ingest_cloud(
    root: Path = config.ROOT,
    *,
    sources: Sequence[str] = (),
    client: OpenSearchClient | None = None,
    ingest_time: datetime | None = None,
    index_prefix: str = config.EVENTS_INDEX_PREFIX,
    refresh: bool = True,
    batch_size: int = 500,
    dry_run: bool = False,
) -> list[IngestResult]:
    """Ingest all selected cloud sources into OpenSearch."""
    return ingest_domain(
        "cloud",
        root,
        sources=sources,
        client=client,
        ingest_time=ingest_time,
        index_prefix=index_prefix,
        refresh=refresh,
        batch_size=batch_size,
        dry_run=dry_run,
    )
