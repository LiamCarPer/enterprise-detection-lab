# Telemetry Ingestion

`edl ingest` loads the sampled Entra ID, Windows endpoint, AWS CloudTrail, Microsoft 365, and GitHub contracts into OpenSearch. The pipeline is deliberately small, but it treats ingestion as production software: validate first, normalize to a stable shape, classify each event, deduplicate deterministically, and make replay idempotent.

```text
telemetry/sources/*.yaml
        │
        ▼
sample dataset + SHA-256 check
        │
        ▼
preflight: schema, required fields, UTC timestamps, dedup key, classifier
        │
        ▼
canonical event + deterministic OpenSearch _id
        │
        ▼
bulk index into edl-events-<source>-YYYY.MM.DD
```

## Commands

```bash
make lab-up
make lab-bootstrap
make ingest-identity
make ingest-endpoint
make ingest-cloud
make ingest-saas
make ingest-network
make ingest-kubernetes
```

Or directly:

```bash
edl ingest identity
edl ingest identity --source entra-signin
edl ingest identity --dry-run
edl ingest identity --json
edl ingest endpoint
edl ingest endpoint --source sysmon
edl ingest endpoint --dry-run
edl ingest cloud
edl ingest cloud --dry-run
edl ingest saas
edl ingest saas --dry-run
edl ingest network
edl ingest network --dry-run
edl ingest kubernetes
edl ingest kubernetes --dry-run
```

`--dry-run` performs the full preflight and prints the target indices without contacting OpenSearch. `--source` accepts one source or a comma-separated list. `--no-refresh` skips the post-ingest count because OpenSearch cannot report an accurate count before the next refresh.

## Preflight

Ingestion fails before writing if any event violates the source contract:

- the sample path is missing or its SHA-256 does not match the contract;
- the dataset is not a non-empty JSON array;
- an event is not an object;
- a declared `required_fields` value is missing or empty;
- the event-time field is missing, invalid, or naive (no timezone);
- a normalizer is not registered for the source;
- the source contract has no `dedup_key` or `event_classes`;
- a classifier returns an event class that the contract does not declare.

The error names the source and, where possible, the dataset item. This is intentionally strict: a partially ingested dataset is worse than a failed ingest.

## Canonical event

Common fields:

| Field | Meaning |
|---|---|
| `@timestamp` | Event time in UTC; used by Dashboards and time-based queries. |
| `event_time` | Normalized event time. Separate from ingest time. |
| `ingest_time` | When the lab ingested the event. |
| `source` | Source contract ID, for example `entra-signin`. |
| `event_class` | Event class. Sources without a classifier use the first declared class; Sysmon and Windows Security classify per event. |
| `event_id` | Native event identifier when the source provides one. |
| `event_code` | Numeric provider event code for Windows and Sysmon. |
| `schema_version` | Source contract schema version. |
| `user` | User principal, initiating identity, or target account. |
| `src_ip` | Source IP when the source provides one. |
| `action` | Sign-in action, directory operation, cloud API name, or Windows event action. |
| `result` | Success or failure, using the source's vocabulary. |
| `dedup_key` | Declared key values used for the deterministic ID. |
| `dedup_origin` | `declared` when the contract key was complete; `hash` for the fallback. |
| `raw` | Original event. Mapped but not indexed. Synthetic data only in this lab. |

Entra sign-in additions: `app`, `auth_requirement`, `is_interactive`, `conditional_access_status`, `risk_level`, and `device.os` / `device.browser`.

Entra audit additions: `app` and `resource.name` / `resource.type` / `resource.count`.

Sysmon additions:

- `host`, `user`, and `event_code`
- `process.name`, `process.image`, `process.command_line`, `process.guid`, `process.id`, `process.parent_name`, `process.parent_image`, `process.parent_command_line`
- `network.source_ip`, `network.source_port`, `network.destination_ip`, `network.destination_port`, `network.protocol`
- `file.target_filename`
- `registry.target_object`, `registry.details`
- `dns.query_name`, `dns.query_results`

Windows Security additions:

- `host`, `user`, `event_code`, `action`, `result`, `src_ip`
- `logon_type`, `status`, `subject_user`, `service_name`, `task_name`

Sysmon `EventID` maps to `process_creation` (1), `network_connection` (3), `process_access` (10), `file_create` (11), `registry_set` (12–14), `dns_query` (22), or `other`. Windows Security maps authentication and account-management event IDs, with `other` for unsampled events. The classification is part of the canonical event and is filterable in OpenSearch.

AWS CloudTrail additions:

- `user`, `identity_type`, `identity_arn`, `src_ip`, `user_agent`
- `action` (the API name), `service` (the event source), `account`, `region`
- `event_id` (the CloudTrail UUID), `result`, and `error_code`

CloudTrail management events use the declared `management_event` class. The raw request and response bodies remain available in `raw` but are not indexed.

SaaS additions:

- Microsoft 365: `workload`, `record_type`, `object_id`, `rule_name`, `forward_to`, `forward_domain`, `forward_domains`, and `forward_external`
- GitHub: `organization`, `repository`, `target_user`, `role` (from `permission`), `user_agent`, and `service=github`

Microsoft 365 event classes follow the operation and workload: mailbox permission grants map to `mailbox_permission`, `MailItemsAccessed` maps to `mail_access`, Exchange maps to `mailbox`, SharePoint/OneDrive to `sharepoint`, Teams to `teams`, and other workloads to `audit`. GitHub maps `git.*` actions to `git`, login actions to `authentication`, and other audit actions to `audit_log`.

Network additions:

- Zeek: `network.*`, `dns.query_name`, `dns.query_type`, `dns.query_length`, `http.*`, `tls.*`, `flow_id`, `network_log`, `bytes_sent`, and `bytes_received`
- Suricata: `network.*`, `alert.signature`, `alert.category`, `alert.severity`, `dns.*`, `http.*`, `tls.*`, `flow_id`, `network_log`, and byte counts

Zeek uses `_path` for event classification, and Suricata uses `event_type`. Both sources accept ISO 8601 event times; Zeek also accepts epoch seconds.

Kubernetes additions:

- Kubernetes audit: `user`, `action`, `result`, `resource_name`, `namespace`, `pod`, `response_status`, `audit_stage`, `privileged`, and `src_ip`
- Falco: `rule_name`, `priority`, `host`, `user`, `namespace`, `pod`, `container`, `src_ip`, and `process`

Kubernetes audit normalizes the API verb, object reference, response status, and privileged-container flag. Falco normalizes runtime alert fields and container context from `output_fields`.

Microsoft 365 forwarding recipients are read from both `Parameters` and `OperationProperties`, including `New-InboxRule`, `Set-InboxRule`, and `UpdateInboxRules`. Domains listed in [`config/tenant.yaml`](../config/tenant.yaml) are treated as internal; `forward_external` is true when any recipient domain is outside that list. The tenant configuration is schema-validated before ingestion and during `edl validate`.

The canonical fields are mapped in [`lab/bootstrap/opensearch/events-template.json`](../lab/bootstrap/opensearch/events-template.json). Unknown fields remain dynamically mapped; update the template when a field becomes part of the query contract.

## Time semantics

- Timestamps must include an offset or `Z`.
- Naive timestamps are rejected.
- Offsets are normalized to UTC.
- The daily index is chosen from the normalized event time, not the ingest time.
- Late and out-of-order events are accepted and land in the index for their event date.
- `ingest_time` is assigned by the lab at ingest and is not trusted from the source.

## Deduplication and replay

The OpenSearch document ID is:

```text
sha256(source_id + canonical JSON of the declared key values)
```

If any declared key value is missing, the fallback hashes the source ID and the full raw event. The fallback is deterministic but is a safety net, not a substitute for a complete contract.

Writes use the `index` bulk action. Replaying the same event overwrites the same document ID instead of creating a duplicate. The source contract's `dedup_key` is the primary control; the hash fallback prevents silent loss when a source violates its contract.

In-batch duplicates are collapsed before writing and reported as `duplicates`. The first occurrence wins when two events share a deterministic ID. Across replays, the document count stays stable and changed content for the same ID overwrites the prior document.

## Index layout

```text
edl-events-entra-signin-2026.11.01
edl-events-entra-audit-2026.11.01
edl-events-sysmon-2026.11.01
edl-events-windows-security-2026.11.01
edl-events-aws-cloudtrail-2026.11.01
edl-events-m365-audit-2026.11.25
edl-events-github-audit-2026.11.25
```

The `edl-events-*` index template applies one shard, zero replicas, UTC date fields, keyword fields for identity, endpoint, cloud, and SaaS pivots, and disabled indexing for `raw`.

## Result fields

| Field | Meaning |
|---|---|
| `read` | Events read from the dataset. |
| `unique` | Events after in-batch deduplication. |
| `duplicates` | Events collapsed by duplicate deterministic IDs. |
| `written` | Documents sent to OpenSearch. |
| `indices` | Target indices. |
| `counts` | Post-refresh document counts per index. Empty with `--no-refresh`. |
| `mode` | `dry-run` or `ingested`. |

## Failure behavior

- Preflight failures abort the affected source before any write.
- OpenSearch HTTP or bulk-item errors abort with the first rejected item.
- There is no cross-source transaction. If one source succeeds and a later source fails, the successful source remains ingested and is safe to replay.
- `--no-refresh` is faster but does not return document counts.

## Status

All eleven sampled sources move from `sampled` to `ingested` after a successful lab run. They move to `validated` only after detection replay and regression tests pass. The generated [telemetry matrix](telemetry-matrix.md) records the current status.

## Known gaps

- All contracted sources are normalized currently, including Kubernetes audit and Falco runtime alerts.
- The samples are small; they demonstrate contract and pipeline behavior, not volume.
- Sysmon field coverage depends on the Sysmon configuration; the sample covers process creation only.
- Windows Security advanced audit policy determines which events exist; the sample covers logon success and failure.
- CloudTrail data events, organization trails, and cross-account delivery are not sampled.
- There is no backpressure, retry queue, dead-letter store, or checkpointing.
- The bulk client retries nothing; a failed command is safe to rerun because writes are idempotent.
- `raw` is retained for triage. A production pipeline would apply redaction before storage.
