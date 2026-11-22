# Telemetry Contracts

`telemetry/sources/*.yaml` is the source of truth for every telemetry source in the lab. The generated [`docs/telemetry-matrix.md`](../docs/telemetry-matrix.md) is derived from these contracts; do not edit the matrix by hand.

## Contract fields

Each contract declares:

- source ID, name, provider, and product
- event classes
- contract schema version and status
- owner
- event-time and ingest-time fields
- timezone and ordering
- deduplication key
- required fields
- sensitive fields
- expected volume, latency, retention, and cost
- late-arrival and duplicate expectations
- known gaps
- optional sample data with license, provenance, and SHA-256

The machine-readable schema is [`schemas/telemetry-source.schema.json`](../schemas/telemetry-source.schema.json).

## Status

| Status | Meaning |
|---|---|
| `documented` | Contract exists; no sample yet. |
| `sampled` | A small synthetic or public sample exists. |
| `ingested` | The sample has been loaded into the lab. |
| `validated` | Replay and query tests pass. |

The repository currently has five sources with samples: Entra sign-in, Entra audit, Sysmon, Windows Security, and AWS CloudTrail. The other six are documented and receive samples with their detection commits.

## Ingest

Identity and endpoint sources are loaded with:

```bash
edl ingest identity
edl ingest endpoint
edl ingest endpoint --source sysmon --dry-run
```

Ingestion checks the sample hash and required fields, rejects naive timestamps,
normalizes to the canonical event shape, classifies per-event where needed, and
uses deterministic document IDs so replay is idempotent. Sysmon and Windows
Security include the declared `Channel` field so the dedup key is exercised
directly rather than falling back to a hash. See
[`docs/ingestion.md`](../docs/ingestion.md).

A source moves to `ingested` after a successful lab load and to `validated` only
after replay and query tests pass. Update the contract and regenerate the matrix
when the status changes.

## Event time and deduplication

- All timestamps are normalized to UTC at ingest.
- Naive timestamps are rejected.
- Event time and ingest time are stored separately.
- Deduplication uses the declared key, with a deterministic hash fallback.
- Late, duplicate, and out-of-order events are expected and tested.

## Add a source

1. Copy an existing source contract.
2. Set a unique lowercase ID and complete every required field.
3. Add synthetic or public, license-compatible sample data under `lab/datasets/`.
4. Record the sample path, license, provenance, and SHA-256.
5. Add the dataset to `lab/datasets/manifest.yaml`.
6. Run:

```bash
edl validate
edl telemetry matrix
edl telemetry matrix --check
```

7. Open a PR. `make check` must pass.

## Data rules

- No PII, secrets, real employer data, or malware.
- Public datasets must include a license and provenance note.
- Large datasets are downloaded by script and never committed.
- Do not edit `docs/telemetry-matrix.md` by hand.
