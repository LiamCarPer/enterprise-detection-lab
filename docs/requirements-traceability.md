# Engineering Requirements Traceability

This document maps engineering requirements for a detection platform to artifacts in this repository. It is a coverage index: pick a requirement, follow the artifact, inspect the evidence.

It is a directional engineering synthesis, not a formal standard or compliance certification. Requirements vary by organization, telemetry stack, and threat model.

## Matrix

| Requirement | Evidence standard | Repository artifact | Current evidence | Status |
|---|---|---|---|---|
| **Telemetry contracts** | Source fields, event time, ingest time, deduplication, required fields, latency, retention, cost, and known gaps | `telemetry/sources/`, `docs/telemetry-matrix.md` | 11 source contracts, generated matrix, hash checks | Complete |
| **Normalization and schema drift** | Canonical event shape, UTC enforcement, versioned mappings, tests for source variation | `src/edl/ingest.py`, `lab/bootstrap/opensearch/events-template.json`, tests | Identity and endpoint normalizers, per-event classification, index mappings | In progress |
| **Detection-as-code** | Rules are versioned, reviewed, tested, converted, deployed, and retired like software | `detections/`, `docs/artifact-model.md`, `.github/workflows/` | Package contract, schema, fixtures, reference template; CI planned | In progress |
| **Detection validation and regression** | Replay, attack simulation, negative tests, regression tests, and backend query checks | `src/edl/validation.py`, `src/edl/detection.py`, `detections/*/tests/`, `conformance/` | Artifact validation, OpenSearch fixture replay, and lab tests; CI replay planned | In progress |
| **Benign baseline and false-positive control** | Measures noise against realistic benign activity, not an idle lab | `lab/`, `detections/*/fixtures/benign.json`, reports | Fixture contract and reference benign fixture; workload generator planned | Planned |
| **Detection quality metrics** | Precision, recall, false-positive rate, latency, sample size, method, and limitations | `schemas/metrics.schema.json`, `detections/*/metrics.json` | Metrics schema and reference metrics file; real measurements planned | Planned |
| **Enterprise telemetry breadth** | Identity, endpoint, cloud, SaaS, network, and Kubernetes sources | `telemetry/sources/`, `docs/telemetry-matrix.md`, `lab/` | 11 contracts across six domains; 5 ingested, 6 documented | In progress |
| **Cloud and identity depth** | Entra/AD/Okta, AWS/Azure/GCP audit, IAM, token and session abuse | `detections/identity/`, `detections/cloud/`, `investigations/` | Identity, endpoint, and cloud ingestion complete; detection content next | In progress |
| **Threat modeling and ATT&CK mapping** | Attacker TTPs, attack paths, evasion, and telemetry implications | `docs/threat-model.md`, detection metadata, `investigations/` | ATT&CK field in detection schema; threat model planned | Planned |
| **Incident investigation** | Timeline, evidence, scope, containment, recovery, and lessons learned | `investigations/`, runbooks | Investigation schema, reference package, evidence rules | In progress |
| **Automation and response safety** | Enrichment, triage, evidence capture, containment proposals, approval gates, and effect verification | `automation/` | Not implemented | Planned |
| **Software engineering quality** | Typed Python, focused modules, error handling, tests, deterministic outputs, coverage gate | `src/edl/`, `tests/`, `Makefile`, `pyproject.toml` | Typed package, unit/integration/lab tests, 90% coverage gate | Complete |
| **Backend portability** | Sigma plus native queries, backend-specific translation, and query validation | `detections/*/queries/`, `schemas/detection.schema.json` | OpenSearch query contract; Sigma rule present in template; KQL/Spl planned | In progress |
| **Data safety and provenance** | Synthetic or licensed data, hashes, provenance, no production data, no secrets | `lab/datasets/manifest.yaml`, `telemetry/sources/`, validation | SHA-256 checks, manifest, synthetic samples, data rules | Complete |
| **Operational documentation** | Architecture, setup, CLI, ingestion, limitations, and troubleshooting | `README.md`, `docs/`, `lab/README.md` | Architecture, ingestion, artifact, CLI, and lab docs | Complete |

## Coverage summary

| Metric | Current |
|---|---|
| Requirements mapped | 15 / 15 |
| Telemetry source contracts | 11 (5 ingested, 6 documented) |
| Identity, endpoint, and cloud ingestion | Complete |
| Detection packages implemented | 1 tested detection (`DET-IDN-001`); 5 planned |
| Detection testing | Fixture replay, pass/fail evaluation, and metrics generation complete |
| Investigations implemented | 0 production investigations; contract and template complete |
| CI and detection metrics | Planned |
| Automation | Planned |

The mapping is complete. The implementation is not. Identity, endpoint, and cloud telemetry are ingested; five remaining detections, two investigations, CI, and aggregated metrics are next.

## How to use this document

1. Choose the requirement relevant to the change.
2. Follow the artifact column to the implementation.
3. Inspect the evidence and status.
4. Treat **Planned** as not implemented, regardless of how the capability is described elsewhere.
5. Update the row when the evidence changes.

## What this document is not

- It is not a compliance certification.
- It is not a substitute for organization-specific requirements or threat models.
- It is not static. It is updated as artifacts are implemented, tested, and reviewed.
