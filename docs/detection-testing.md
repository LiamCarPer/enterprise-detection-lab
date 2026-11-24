# Detection Testing

`edl detection test` executes a detection package against its fixtures using the local OpenSearch lab. It verifies the native query, the telemetry normalization path, and the package's expected positive, negative, and benign behavior.

## Commands

```bash
make lab-up
make lab-bootstrap

edl detection test --id DET-END-000
edl detection test
edl detection test --include-templates
edl detection test --json
edl detection test --write-metrics
```

By default, `edl detection test` runs every non-template detection. Use `--id` to run one package, including the reference template, or `--include-templates` to include templates in an all-detection run.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Every selected detection passed. |
| 1 | At least one detection failed. |
| 2 | The runner could not execute. |

## Execution flow

1. Load `meta.yaml`, the OpenSearch query, source contracts, and all three fixture files.
2. Require every fixture to be marked `synthetic: true`.
3. Normalize each raw fixture event through the same source normalizer used by ingestion.
4. Create a temporary index such as `edl-events-detect-det-idn-001-<random>`.
5. Bulk-index the normalized fixtures with unique test IDs.
6. Execute the committed query with enough `size` to return every fixture.
7. Compare returned IDs against the expected fixture kind.
8. Run the query several times to capture local latency.
9. Delete the temporary index.

The temporary index matches the `edl-events-*` template, so canonical field mappings apply.

## Pass criteria

- Every positive fixture must match.
- No negative fixture may match.
- No benign fixture may match.

A detection with a missed positive or any unexpected hit fails the command.

## Metrics

`--write-metrics` writes `metrics.json` only for passing detections.

| Field | Meaning |
|---|---|
| `sample_size` | Total fixtures evaluated. |
| `precision` | `TP / (TP + FP)`. |
| `recall` | `TP / (TP + FN)`. |
| `false_positive_rate` | `FP / (FP + TN)`. |
| `latency_ms_p50` | Median local query latency. |
| `latency_ms_p95` | 95th percentile local query latency. |
| `method` | How the measurements were produced. |
| `limitations` | Sample, environment, and query-path caveats. |

These are **synthetic fixture measurements**, not production detection quality. The committed metrics include that limitation explicitly.

Generate the aggregate report with:

```bash
edl detection report
edl detection report --check
```

The output is [`reports/detection-metrics.md`](../reports/detection-metrics.md).

## Correlation detections

A detection may declare an ordered sequence in `meta.yaml`:

```yaml
correlation:
  window_seconds: 1800
  group_by:
    - user
  steps:
    - source: entra-signin
      event_class: sign_in
    - source: entra-audit
      event_class: audit
```

The runner executes the native query, then evaluates the returned events as
ordered scenarios. Fixtures can use a `scenario` field to group events into one
case. Correlation metrics are **scenario-level**: each scenario contributes one
TP/FN/FP/TN result, not one result per event. The metrics `evaluation_unit`
field and report column make that distinction explicit.

`DET-IDN-003`, `DET-SAA-003`, `DET-SAA-004`, and `DET-SAA-005` are the reference correlation detections. They sequence identity sign-in with audit events, a Microsoft 365 mailbox rule, mailbox or group delegation, and self-delegation followed by mail access.

## Baseline evaluation

Use `edl detection baseline` to measure a detection query against a benign
activity corpus:

```bash
edl detection baseline \
  --id DET-END-001 \
  --dataset lab/datasets/synthetic/benign-baseline/endpoint.json
```

The result reports the number of cases, matched cases, and the false-positive
rate. Event detections are measured per event; correlation detections are
measured per scenario. `--query` accepts an alternative query path relative to
the detection package, which makes before/after tuning reproducible.

The endpoint tuning result is documented in
[`reports/false-positive-tuning.md`](../reports/false-positive-tuning.md). The
identity, cloud, SaaS, network, Kubernetes, and correlation results are summarized in
[`reports/benign-baseline-results.md`](../reports/benign-baseline-results.md).

## Fixture sources

Fixtures use the repository envelope:

```json
{
  "event": { "...": "raw source event" },
  "source": "sysmon",
  "synthetic": true,
  "note": "optional"
}
```

The runner normalizes `event` with the matching telemetry source contract. Detection queries therefore use canonical fields such as `event_code`, `process.image`, `risk_level`, or `action`, not raw source names.

## Sigma boundary

The Sigma rule remains the vendor-neutral representation of the detection. The current runner executes the native OpenSearch query. Sigma conversion and cross-backend equivalence are not part of this test yet, and the metrics limitations state that explicitly.

## Reference artifact

[`detections/endpoint/_template`](../detections/endpoint/_template) is the executable reference package:

```bash
edl detection test --id DET-END-000
edl detection test --id DET-IDN-001
```

The template is a contract reference. `DET-IDN-001` is the first real detection with a 15-event corpus, runbook, and committed metrics.
