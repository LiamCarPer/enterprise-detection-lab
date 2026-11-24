# Local Lab

The lab is a local, reproducible environment for OpenSearch, OpenSearch Dashboards, and the Microsoft Kusto emulator. It is for development and testing only. It is not a production deployment.

## Prerequisites

- Docker Engine with Docker Compose v2
- Python 3.12
- `uv`
- At least 16 GB RAM recommended; the containers request about 8 GB total
- Linux x86-64 for the Kusto emulator; the Microsoft image does not support ARM

## Start

```bash
cp .env.example .env
make install
make lab-up
make lab-status
make lab-bootstrap
make ingest-identity
make ingest-endpoint
make ingest-cloud
make ingest-saas
make ingest-network
```

`make lab-up` starts:

| Service | URL | Notes |
|---|---|---|
| OpenSearch | http://127.0.0.1:9200 | Security plugin disabled for local use |
| OpenSearch Dashboards | http://127.0.0.1:5601 | Kibana-compatible UI |
| Kusto emulator | http://127.0.0.1:18080 | No authentication; localhost only |

`make lab-bootstrap` creates the OpenSearch index templates, the Kusto tables in `NetDefaultDB`, and the local DuckDB schema. The Kusto emulator uses `NetDefaultDB` as its default database; the bootstrap uses `create-merge` so it is safe to run repeatedly.

## Ingest telemetry

```bash
make ingest-identity
make ingest-endpoint
make ingest-cloud
make ingest-saas
make ingest-network
```

Identity ingestion normalizes the Entra sign-in and audit samples. Endpoint
ingestion normalizes Sysmon and Windows Security, classifies each event from its
`EventID`, and validates the declared `Channel` dedup key. Cloud ingestion
normalizes the AWS CloudTrail sample, including account, region, identity, and
API context. SaaS ingestion normalizes the Microsoft 365 and GitHub audit samples,
including actor, workload, organization, repository, and forwarding context.
Network ingestion normalizes Zeek and Suricata samples, including addresses,
ports, protocol, DNS, HTTP, TLS, alerts, and flow metadata. All
paths validate required fields and UTC timestamps and bulk-index into daily
`edl-events-<source>-*` indices. Writes use deterministic
document IDs, so replaying the same dataset is idempotent.

Useful variants:

```bash
uv run edl ingest identity --dry-run
uv run edl ingest endpoint --source sysmon --json
uv run edl ingest cloud --dry-run
uv run edl ingest saas --dry-run
uv run edl ingest endpoint --no-refresh
```

See [`docs/ingestion.md`](../docs/ingestion.md) for the canonical event model,
deduplication, index layout, and failure behavior.

## Stop

```bash
make lab-down
```

## Reset

```bash
make lab-reset
```

This removes the containers and the named volumes. It deletes local lab data.

## Logs

```bash
make lab-logs
uv run edl lab logs opensearch
```

## Security

- OpenSearch security is disabled **only** for this local lab.
- The Kusto emulator has **no authentication**. It must never be exposed beyond localhost.
- All ports bind to `127.0.0.1`.
- Do not put production data, customer data, PII, credentials, or malware in the lab.
- Use synthetic or public, license-compatible data only.

## Pinned versions

See [`lab/versions.lock`](versions.lock). The Compose file pins image digests for reproducibility. Treat a digest change as a dependency upgrade.

## Troubleshooting

### OpenSearch exits or is unhealthy

- Confirm Docker has enough memory. The default heap is 2 GB.
- Check `docker compose logs opensearch`.
- Increase `OPENSEARCH_JAVA_OPTS` in `.env` if needed.

### Kusto emulator does not start

- Confirm the host is Linux x86-64 with AVX2 support.
- The image is several GB; the first pull can take time.
- Check `docker compose logs kusto`.
- The emulator has no auth and no managed ingestion service; use ingestion commands or the bootstrap script.

### Port already in use

Change the port in `.env` and restart:

```bash
OPENSEARCH_PORT=9201
```

Then update the matching `EDL_OPENSEARCH_URL` value.

The default Kusto host port is `18080` to avoid collisions with common local
services on `8080`. Override `KUSTO_PORT` and `EDL_KUSTO_URL` together if
needed.

### Docker permission denied

Add your user to the `docker` group and start a new shell, or run Docker through a rootless setup. Do not run the whole repository as root.
