# Capability Matrix

This matrix tracks the engineering capabilities implemented in the lab and the artifacts that provide evidence for each one. A capability is **Complete** only when the artifact exists, is tested, and can be inspected.

## Status meanings

| Status | Meaning |
|---|---|
| **Complete** | Artifact exists, tests pass, and the behavior is documented. |
| **Tested** | Detection fixtures pass the replay runner; production validation is pending. |
| **In progress** | Part of the artifact exists; the remaining work is identified. |
| **Planned** | Not implemented yet. |

## Matrix

| Capability | What good evidence looks like | Artifacts | Status |
|---|---|---|---|
| **Telemetry contracts** | Source fields, event time, ingest time, deduplication, required fields, latency, retention, cost, and known gaps | `telemetry/sources/`, `docs/telemetry-matrix.md` | Complete |
| **Identity telemetry** | Normalized Entra sign-in and audit events, UTC enforcement, deterministic IDs, idempotent replay | `src/edl/ingest.py`, `lab/datasets/synthetic/entra-*`, `docs/ingestion.md` | Complete |
| **Endpoint telemetry** | Normalized Sysmon and Windows Security events, per-event classification, declared dedup keys | `src/edl/ingest.py`, `lab/datasets/synthetic/sysmon`, `lab/datasets/synthetic/windows-security` | Complete |
| **Cloud telemetry** | AWS CloudTrail normalization, identity and request context, replay verification | `telemetry/sources/aws-cloudtrail.yaml`, `src/edl/ingest.py` | Complete |
| **SaaS telemetry** | Microsoft 365 and GitHub audit normalization, actor and resource context, replay verification | `telemetry/sources/m365-audit.yaml`, `telemetry/sources/github-audit.yaml`, `src/edl/ingest.py` | Complete |
| **Network telemetry** | Zeek and Suricata normalization, DNS, HTTP, TLS, alert, and flow context, replay verification | `telemetry/sources/zeek.yaml`, `telemetry/sources/suricata.yaml`, `src/edl/ingest.py` | Complete |
| **Detection engineering** | Versioned packages with hypothesis, telemetry contract, Sigma rule, native query, fixtures, runbook, and metrics | `detections/`, `schemas/detection.schema.json` | In progress |
| **Detection validation** | Positive, negative, and benign fixtures; schema checks; backend query checks; regression tests | `src/edl/validation.py`, `detections/*/tests/`, `tests/` | In progress |
| **Investigation** | Timeline, queries, evidence, response, lessons, and an executive summary for a complete attack chain | `investigations/`, `schemas/investigation.schema.json` | Complete |
| **Detection quality** | Precision, recall, false-positive rate, latency, sample size, method, and limitations | `schemas/metrics.schema.json`, `detections/*/metrics.json`, `reports/` | In progress |
| **Automation** | Enrichment, triage, evidence capture, and approval-gated containment proposals | `automation/` | Planned |
| **Software engineering** | Typed Python, focused modules, schema validation, unit and integration tests, deterministic outputs, coverage gate | `src/edl/`, `tests/`, `Makefile`, `pyproject.toml` | Complete |
| **Documentation** | Architecture, contracts, operating instructions, limitations, and generated matrices | `README.md`, `docs/`, `lab/README.md` | Complete |
| **Kubernetes** | Contract and sample followed by domain-specific detections | `telemetry/sources/`, `detections/` | Planned |

## Current evidence

| Artifact | Status | Evidence |
|---|---|---|
| `README.md` | Complete | Project overview, architecture, quick start, scope, and limitations |
| `docs/artifact-model.md` | Complete | Detection and investigation package contracts |
| `compose.yaml` + `lab/` | Complete | Local OpenSearch, Dashboards, Kusto, and DuckDB stack with pinned images and bootstrap |
| `src/edl/` | Complete | Validation, reporting, ingestion, scaffolding, and lab lifecycle |
| `telemetry/sources/` + `docs/telemetry-matrix.md` | Complete | 11 contracts (7 ingested, 4 documented) with generated matrix and freshness check |
| `src/edl/ingest.py` + `docs/ingestion.md` | Complete | Identity, endpoint, cloud, and SaaS normalization, classification, deduplication, and idempotent bulk ingest |
| `detections/endpoint/_template` + `investigations/_template` | Complete | Working reference packages and `edl new` scaffolding |
| `detections/identity`, `detections/endpoint`, `detections/cloud`, `detections/saas`, `detections/network` | Tested | Eleven core detections, including one sequence correlation, with runbooks and committed metrics |
| `investigations/01-identity-to-cloud` + `investigations/02-endpoint-to-cloud` | Tested | Evidence hashes, timelines, queries, response, lessons, and linked detection checks |
| `src/edl/detection.py` + `docs/detection-testing.md` | Complete | Fixture normalization, temporary-index replay, pass/fail scoring, and metrics generation |
| `tests/` + `Makefile` | Complete | Unit, integration, and lab tests; 90% statement-coverage gate |
| `.github/workflows/ci.yml` | Complete | Quality job plus OpenSearch-backed ingestion, detection, and investigation tests |
| `reports/detection-metrics.md` | Complete | Aggregated fixture metrics for eleven detections with explicit limitations |
| `lab/datasets/synthetic/benign-baseline/` + `reports/` | Complete | Nine benign corpora, including SaaS, network, and a scenario baseline, plus an 8/20 to 0/20 endpoint tuning result |
| `detections/exceptions.yaml` + `docs/exception-policy.md` | Complete | Reviewed exceptions with owner, scope, expiry, change ticket, and compensating controls |
| `docs/capability-matrix.md` + `docs/requirements-traceability.md` | Complete | Capability and engineering-requirement traceability |

## Next evidence

The next work is breadth and depth:

- Kubernetes telemetry contract and sample.
- Additional SaaS, network, and Kubernetes detections.
- Broader benign coverage and automation.

## Evidence standards

- Every **Complete** artifact exists and can be inspected.
- Detections include tests, replay, benign baselines, and metrics before being marked production.
- Investigations distinguish observed evidence from inference.
- Metrics include sample size, method, and limitations.
- Design documents record alternatives, non-goals, and trade-offs.

The matrix is updated as work lands. **Planned** means planned, not implemented.
