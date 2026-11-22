# Identity Telemetry Ingestion

`edl ingest identity` loads the sampled Entra ID sign-in and audit contracts into OpenSearch. The pipeline is deliberately small, but it treats ingestion as production software: validate first, normalize to a stable shape, deduplicate deterministically, and make replay idempotent.

```text
telemetry/sources/*.yaml
        │
        ▼
sample dataset + SHA-256 check
        │
        ▼
preflight: schema, required fields, UTC timestamps, dedup key
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
```

Or directly:

```bash
edl ingest identity
edl ingest identity --source entra-signin
edl ingest identity --dry-run
edl ingest identity --json
edl ingest identity --no-refresh
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
- the source contract has no `dedup_key` or `event_classes`.

The error names the source and, where possible, the dataset item. This is intentionally strict: a partially ingested dataset is worse than a failed ingest.

## Canonical event

Common fields:

| Field | Meaning |
|---|---|
| `@timestamp` | Event time in UTC; used by Dashboards and time-based queries. |
| `event_time` | Normalized event time. Separate from ingest time. |
| `ingest_time` | When the lab ingested the event. |
| `source` | Source contract ID, for example `entra-signin`. |
| `event_class` | Declared event class, for example `sign_in`. |
| `schema_version` | Source contract schema version. |
| `user` | User principal or initiating identity. |
| `src_ip` | Source IP when the source provides one. |
| `action` | Sign-in action or directory operation. |
| `result` | Success or failure, using the source's vocabulary. |
| `dedup_key` | Declared key values used for the deterministic ID. |
| `dedup_origin` | `declared` when the contract key was complete; `hash` for the fallback. |
| `raw` | Original event. Mapped but not indexed. Synthetic data only in this lab. |

Entra sign-in additions: `app`, `auth_requirement`, `is_interactive`, `conditional_access_status`, `risk_level`, and `device.os` / `device.browser`.

Entra audit additions: `app` and `resource.name` / `resource.type` / `resource.count`.

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
```

The `edl-events-*` index template applies one shard, zero replicas, UTC date fields, keyword fields for identity pivots, and disabled indexing for `raw`.

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

The two identity sources move from `sampled` to `ingested` after a successful lab run. They move to `validated` only after detection replay and regression tests pass. The generated [telemetry matrix](telemetry-matrix.md) records the current status.

## Known gaps

- Only the two Entra identity sources are normalized in Gate 1.
- The sample has two events per source; it demonstrates semantics, not volume.
- There is no backpressure, retry queue, dead-letter store, or checkpointing.
- The bulk client retries nothing; a failed command is safe to rerun because writes are idempotent.
- `raw` is retained for triage. A production pipeline would apply redaction before storage.
