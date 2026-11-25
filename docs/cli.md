# CLI

The `edl` CLI is the repository’s control surface for validation and the local lab.

## Install

```bash
uv sync --all-extras
```

## Validation

```bash
edl validate
edl validate --path detections/identity/oauth-consent
edl validate --strict
edl validate --sigma
edl validate --json
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Validation passed |
| 1 | Validation failed |
| 2 | Validation could not run |

`--strict` promotes warnings to errors. `--sigma` requires the `sigma` CLI
(`sigma-cli`) and runs `sigma check` on each detection rule.

## Reports

```bash
edl report
edl report --format json
edl report --format markdown
```

The JSON report is designed to be machine-readable and follows
`schemas/validation-report.schema.json`.

## Telemetry matrix

```bash
edl telemetry matrix
edl telemetry matrix --check
edl telemetry matrix --output docs/telemetry-matrix.md
```

`--check` fails when the committed matrix is stale relative to
`telemetry/sources/*.yaml`.

## Scaffolding

```bash
edl new detection --domain identity --slug oauth-consent --id DET-IDN-001 --title "OAuth consent grant"
edl new investigation --slug identity-to-cloud --id INV-001 --title "Identity to cloud"
edl new detection --domain identity --slug test --id DET-IDN-999 --title "Test" --dry-run
```

The generated artifact is a valid copy of the working reference template. Edit
the reference behavior before changing status from `draft` to `tested`.

## Ingest telemetry

```bash
edl ingest identity
edl ingest endpoint
edl ingest cloud
edl ingest saas
edl ingest network
edl ingest kubernetes
edl ingest endpoint --source sysmon
edl ingest cloud --dry-run
edl ingest saas --source exchange-message-trace
edl ingest identity --source entra-signin
edl ingest identity --dry-run
edl ingest identity --json
```

The commands validate the sample contract, normalize events to the canonical
identity, endpoint, cloud, SaaS, network, or Kubernetes shape, classify per-event where the source requires
it, use deterministic document IDs, and bulk-index into daily
`edl-events-<source>-YYYY.MM.DD` indices. Replays overwrite the same document
IDs instead of creating duplicates.

`--dry-run` performs preflight only and does not contact OpenSearch.
`--no-refresh` skips the post-ingest count. See
[`ingestion.md`](ingestion.md) for the canonical fields, time semantics, and
failure behavior.

## Detection tests

```bash
edl detection test
edl detection test --id DET-END-000
edl detection test --include-templates
edl detection test --json
edl detection test --write-metrics
```

The runner normalizes each fixture, writes it to a temporary OpenSearch index,
executes the committed query, and checks the positive, negative, and benign
expectations. See [`detection-testing.md`](detection-testing.md).

## Detection metrics report

```bash
edl detection report
edl detection report --check
edl detection report --output reports/detection-metrics.md
```

`--check` fails when the committed report is stale relative to the detection
`metrics.json` files.

## Baseline evaluation

```bash
edl detection baseline \
  --id DET-END-001 \
  --dataset lab/datasets/synthetic/benign-baseline/endpoint.json

edl detection baseline \
  --id DET-END-001 \
  --dataset lab/datasets/synthetic/benign-baseline/endpoint.json \
  --query queries/opensearch-before.json
```

The command executes the detection query against a benign baseline and reports
the match count and false-positive rate. The optional `--query` path is resolved
relative to the detection package.

## Lab

```bash
edl lab up
edl lab status
edl lab wait --timeout 180
edl lab bootstrap
edl lab logs opensearch
edl lab down
edl lab reset --yes
```

`edl lab reset` deletes the named volumes and requires `--yes`.
