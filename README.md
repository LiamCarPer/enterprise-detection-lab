# Enterprise Detection Engineering Lab

[![CI](https://github.com/LiamCarPer/enterprise-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/LiamCarPer/enterprise-detection-lab/actions/workflows/ci.yml)

A reproducible local lab for developing and testing enterprise detection content across identity, endpoint, cloud, SaaS, network, and Kubernetes telemetry.

**Status:** Alpha. Identity, endpoint, cloud, SaaS, network, and Kubernetes telemetry ingestion, fourteen core detections, two investigations, CI, and aggregated fixture metrics are complete. The next focus is broader detection coverage and automation.

[Quick start](#quick-start) · [Architecture](#architecture) · [Project status](#project-status) · [Documentation](#documentation)

## Overview

Detection content is often managed as disconnected rules, saved searches, and screenshots. This project treats detections as versioned software: each detection owns its telemetry contract, tests against positive, negative, and benign behavior, records quality metrics, and links to an investigation runbook.

The lab provides:

- Declarative telemetry contracts for source fields, event time, ingest time, deduplication, required fields, and known gaps.
- A normalized ingestion pipeline with UTC timestamp enforcement, deterministic document IDs, and idempotent bulk writes.
- Detection and investigation package formats with schema validation, fixtures, tests, and metrics.
- A CLI for validation, reporting, ingestion, scaffolding, and local lab lifecycle.
- A Docker Compose lab with OpenSearch, OpenSearch Dashboards, the Kusto emulator, and DuckDB.

All committed telemetry is synthetic or public, licensed, and small enough to inspect.

## Architecture

```text
telemetry/sources/*.yaml
        │
        ▼
  edl ingest <domain>
        │  validate → normalize → classify → deduplicate
        ▼
OpenSearch: edl-events-<source>-YYYY.MM.DD

detections/<domain>/<slug>/
        │
        ▼
  edl validate
        │  schema → required files → fixtures → metrics → links
        ▼
  validation report / CI gate
```

- `telemetry/sources/` defines the contract for each source. The generated [`docs/telemetry-matrix.md`](docs/telemetry-matrix.md) summarizes them.
- `src/edl/ingest.py` normalizes events, assigns deterministic OpenSearch document IDs, and writes in batches.
- `detections/` contains detection packages with Sigma rules, native queries, fixtures, tests, runbooks, and metrics.
- `investigations/` contains evidence-backed incident scenarios and response notes.
- `src/edl/validation.py` enforces the artifact contracts and repository-wide invariants.
- `src/edl/lab.py` manages the local Docker Compose stack and bootstrap files.

The local stack is for development and testing only. OpenSearch security is disabled, the Kusto emulator has no authentication, and all ports bind to `127.0.0.1`.

## Quick start

Requirements: Python 3.12, [uv](https://docs.astral.sh/uv/), and Docker Compose.

```bash
git clone https://github.com/LiamCarPer/enterprise-detection-lab.git
cd enterprise-detection-lab
cp .env.example .env
make install
make check
```

Run the lab and ingest the available telemetry:

```bash
make lab-up
make lab-bootstrap
make ingest-identity
make ingest-endpoint
make ingest-cloud
make ingest-saas
make ingest-network
make ingest-kubernetes
make test-detections
make test-lab
```

Stop the lab without deleting data:

```bash
make lab-down
```

`make check` runs linting, formatting, type checks, artifact validation, telemetry matrix freshness, and the test suite. It enforces a 90% statement-coverage floor on `src/edl`; current coverage is 100%. Lab tests are separate because they require running services.

## Usage

### Validate artifacts

```bash
uv run edl validate
uv run edl validate --strict
uv run edl validate --json
uv run edl report --format markdown
```

### Ingest telemetry

```bash
uv run edl ingest identity
uv run edl ingest endpoint
uv run edl ingest endpoint --source sysmon --dry-run
```

See [`docs/ingestion.md`](docs/ingestion.md) for the canonical event model, time semantics, deduplication, and failure behavior.

### Test detections

```bash
uv run edl detection test
uv run edl detection test --id DET-END-000
uv run edl detection test --write-metrics
```

The runner normalizes fixtures, writes them to a temporary OpenSearch index, executes the committed query, and checks positive, negative, and benign expectations.

See [`docs/detection-testing.md`](docs/detection-testing.md) for the execution flow and metric definitions.

### Detection metrics report

```bash
uv run edl detection report
uv run edl detection report --check
```

The generated report is [`reports/detection-metrics.md`](reports/detection-metrics.md). It aggregates committed fixture metrics and states the synthetic-data limitations explicitly.

### Scaffold artifacts

```bash
uv run edl new detection \
  --domain identity \
  --slug oauth-consent \
  --id DET-IDN-001 \
  --title "OAuth consent grant"

uv run edl new investigation \
  --slug identity-to-cloud \
  --id INV-001 \
  --title "Identity to cloud"
```

### Manage the lab

```bash
uv run edl lab status
uv run edl lab wait --timeout 180
uv run edl lab logs opensearch
uv run edl lab reset --yes   # deletes lab volumes
```

## Telemetry coverage

| Domain | Sources | Status |
|---|---|---|
| Identity | Entra ID sign-in, Entra ID audit | Ingested |
| Endpoint | Sysmon, Windows Security | Ingested |
| Cloud | AWS CloudTrail | Ingested |
| SaaS | Microsoft 365 audit, GitHub audit | Ingested |
| Network | Zeek, Suricata | Ingested |
| Kubernetes | Kubernetes audit, Falco | Ingested |

Each contract records event time and ingest time fields, deduplication keys, required fields, expected latency, retention, cost, and known gaps. The full matrix is generated from the contracts and checked in `make check`.

## Detection coverage

| ID | Domain | Detection | Status |
|---|---|---|---|
| [`DET-END-001`](detections/endpoint/encoded-powershell-non-powershell-parent/) | Endpoint | Encoded PowerShell from a non-PowerShell parent | Tested |
| [`DET-END-002`](detections/endpoint/office-spawns-scripting-host/) | Endpoint | Office application spawns a scripting host | Tested |
| [`DET-IDN-001`](detections/identity/risky-signin-single-factor/) | Identity | Successful risky sign-in with single-factor authentication | Tested |
| [`DET-IDN-002`](detections/identity/service-principal-owner-added/) | Identity | Owner added to a service principal | Tested |
| [`DET-IDN-003`](detections/identity/risky-signin-then-service-principal-owner/) | Identity | Risky sign-in followed by service principal ownership change | Tested |
| [`DET-CLD-001`](detections/cloud/iam-access-key-created/) | Cloud | IAM access key created | Tested |
| [`DET-CLD-002`](detections/cloud/cloudtrail-logging-stopped/) | Cloud | CloudTrail logging stopped | Tested |
| [`DET-SAA-001`](detections/saas/inbox-rule-mail-forwarding/) | SaaS | External inbox rule mail forwarding | Tested |
| [`DET-SAA-002`](detections/saas/github-organization-owner-added/) | SaaS | GitHub organization owner added | Tested |
| [`DET-SAA-003`](detections/saas/risky-signin-then-mail-forwarding/) | SaaS | Risky sign-in followed by mail forwarding rule | Tested |
| [`DET-NET-001`](detections/network/long-txt-dns-query/) | Network | Long TXT DNS query | Tested |
| [`DET-NET-002`](detections/network/high-severity-malware-alert/) | Network | High-severity malware or trojan alert | Tested |
| [`DET-K8S-001`](detections/kubernetes/privileged-pod-created/) | Kubernetes | Privileged pod created | Tested |
| [`DET-K8S-002`](detections/kubernetes/shell-spawned-in-container/) | Kubernetes | Shell spawned in a container | Tested |

A detection is **Tested** when its positive, negative, and benign fixtures pass the OpenSearch replay runner. Production status additionally requires CI and measured operating data.

## Investigation coverage

| ID | Domains | Investigation | Status |
|---|---|---|---|
| [`INV-001`](investigations/01-identity-to-cloud/) | Identity, cloud | Identity persistence to cloud credential access | Tested |
| [`INV-002`](investigations/02-endpoint-to-cloud/) | Endpoint, cloud | Endpoint execution to cloud persistence | Tested |

Investigations are **Tested** when the timeline, evidence, queries, response, and linked detections are complete and the lab query returns the observed evidence.

## Repository layout

```text
.
├── src/edl/                 # CLI, validation, ingestion, and lab lifecycle
├── schemas/                 # JSON schemas for artifact metadata and metrics
├── telemetry/               # Telemetry source contracts
├── detections/              # Detection packages and the reference template
├── investigations/          # Investigation packages and the reference template
├── lab/                     # Compose bootstrap, synthetic datasets, and lab docs
├── docs/                    # Architecture, ingestion, CLI, and status docs
├── reports/                 # Generated detection metrics report
├── tests/                   # Unit, integration, and lab tests
└── .github/workflows/       # CI quality and OpenSearch jobs
```

## Project status

| Component | Status | Notes |
|---|---|---|
| Telemetry contracts | Complete | 11 sources across six domains; 11 ingested |
| Identity ingestion | Complete | Entra sign-in and audit, normalized and replay-safe |
| Endpoint ingestion | Complete | Sysmon and Windows Security, per-event classification |
| Cloud ingestion | Complete | AWS CloudTrail, normalized and replay-safe |
| SaaS ingestion | Complete | Microsoft 365 and GitHub audit, normalized and replay-safe |
| Network ingestion | Complete | Zeek and Suricata, normalized and replay-safe |
| Kubernetes ingestion | Complete | Kubernetes audit and Falco, normalized and replay-safe |
| Detection packages | In progress | Fourteen tested detections; production validation pending |
| Detection testing | Complete | Normalized fixture replay, temporary-index isolation, pass/fail gate, and metrics generation |
| Tested detections | 14 of 14 | All core detections pass fixture replay |
| Investigations | Complete | Two tested investigation packages with hashed evidence |
| Tested investigations | 2 of 2 | `INV-001` and `INV-002` pass evidence and detection-link checks |
| CI | Complete | GitHub Actions quality and OpenSearch-backed test jobs |
| Metrics reporting | Complete | Aggregated fixture metrics for fourteen detections in `reports/detection-metrics.md` |
| Benign baseline | Complete | Thirteen corpora, including two tuning studies and two scenario-level correlation baselines |
| Exception catalog | Complete | Reviewed exceptions with owner, scope, expiry, and compensating controls |
| Correlation detections | Complete | `DET-IDN-003` and `DET-SAA-003` evaluate ordered identity and SaaS sequences |
| Detection depth | In progress | Broader coverage, tuning, and automation across the ingested sources |
| Automation | Planned | Enrichment, triage, evidence, and approval-gated response |

Current focus: broader detection coverage and automation.

## Quality gates

- `make check` and CI must pass.
- A detection is not complete until positive, negative, and benign fixtures pass.
- Native OpenSearch queries must pass `edl detection test` against those fixtures.
- A detection must include a Sigma rule, a native query, false-positive analysis, a runbook, and metrics.
- A production detection must include measured precision, recall, false-positive rate, latency, and limitations.
- An investigation must distinguish observed evidence from inference and include a timeline, queries, evidence, response, and lessons.
- An investigation query must return its observed evidence and every linked detection must pass.
- Telemetry changes must update the contract, sample hash, manifest, and generated matrix together.
- Exceptions must include an owner, narrow scope, change ticket, expiry, and compensating control.

## Design principles

1. **Contracts first.** Every detection declares the telemetry it needs, including timing, quality assumptions, and known gaps.
2. **Reproducible by default.** The same commit, sample data, and commands produce the same local result.
3. **Detection-as-code.** Rules, queries, tests, runbooks, and metrics are versioned and reviewed together.
4. **Test both sides.** Every detection is exercised against adversary behavior and a benign baseline.
5. **Measure quality.** Precision, recall, false positives, latency, and limitations are first-class outputs.
6. **Idempotent operations.** Replaying a dataset overwrites deterministic document IDs rather than creating duplicates.
7. **Document judgment.** Trade-offs, non-goals, and limitations are part of the artifact.
8. **Synthetic or public data only.** No production or customer data in the repository.

## Scope

The project focuses on enterprise IT telemetry and detection engineering workflows: source contracts, normalization, detection packages, validation, investigations, and quality measurement. It runs locally and is not a production service.

Out of scope for this repository:

- Production deployment or production data.
- Commercial EDR or SIEM content.
- Autonomous containment without human approval.
- Multi-tenant platform features.

## Limitations

- The repository is in alpha. The detection and investigation corpus is still small, and production measurements are not included.
- Samples contain a handful of events per source. They demonstrate contract and pipeline behavior, not production volume.
- The lab does not model production scale, backpressure, retries, dead-letter queues, or multi-tenant isolation.
- Measurements are small and will be reported with confidence intervals and explicit limitations.
- No commercial EDR or SIEM licenses are used. The lab relies on open-source tooling and a local Kusto emulator.
- Ingestion is transactional per source. Cross-source ingestion can partially succeed; replay is safe because writes are idempotent.

## Documentation

| Document | Purpose |
|---|---|
| [`docs/ingestion.md`](docs/ingestion.md) | Canonical events, classification, deduplication, and ingest behavior |
| [`docs/artifact-model.md`](docs/artifact-model.md) | Detection and investigation package contracts |
| [`docs/detection-testing.md`](docs/detection-testing.md) | Fixture replay, pass criteria, and metric definitions |
| [`reports/detection-metrics.md`](reports/detection-metrics.md) | Generated aggregate detection metrics and limitations |
| [`reports/false-positive-tuning.md`](reports/false-positive-tuning.md) | Endpoint baseline measurement and before/after tuning analysis |
| [`reports/saas-forwarding-tuning.md`](reports/saas-forwarding-tuning.md) | SaaS forwarding baseline measurement and before/after tuning analysis |
| [`reports/benign-baseline-results.md`](reports/benign-baseline-results.md) | Identity, endpoint, cloud, and scenario baseline results |
| [`docs/exception-policy.md`](docs/exception-policy.md) | Exception types, approval requirements, and review lifecycle |
| [`docs/cli.md`](docs/cli.md) | CLI commands, options, and exit codes |
| [`docs/telemetry-matrix.md`](docs/telemetry-matrix.md) | Generated source contract matrix |
| [`docs/capability-matrix.md`](docs/capability-matrix.md) | Implemented capabilities and evidence |
| [`docs/requirements-traceability.md`](docs/requirements-traceability.md) | Engineering requirements mapped to artifacts |
| [`lab/README.md`](lab/README.md) | Local lab setup, ports, reset, and troubleshooting |
| [`telemetry/README.md`](telemetry/README.md) | Telemetry contract fields and status model |
| [`detections/README.md`](detections/README.md) | Detection package layout and contribution steps |
| [`investigations/README.md`](investigations/README.md) | Investigation package layout and evidence rules |

## Related standards and tools

- [SigmaHQ](https://github.com/SigmaHQ/sigma) and [pySigma](https://github.com/SigmaHQ/pySigma) for vendor-neutral detection rules and conversion.
- [RSigma](https://github.com/timescale/rsigma) for Sigma evaluation, backtesting, and diagnostics.
- [Scythe sigma-regression-testing](https://github.com/scythe-io/sigma-regression-testing) for continuous detection validation and Atomic Red Team mapping.
- [Elastic detection-rules](https://github.com/elastic/detection-rules) and [Splunk contentctl](https://github.com/splunk/contentctl) for detection-as-code testing patterns.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for adversary emulation.
- [OCSF](https://github.com/ocsf/ocsf-schema) for enterprise telemetry normalization.
- [Falco](https://github.com/falcosecurity/falco), [Zeek](https://github.com/zeek/zeek), and [Suricata](https://github.com/OISF/suricata) for runtime and network telemetry.

## Contributing

Open an issue for design discussion before large changes. Run `make check` before opening a pull request. Lab tests require `make lab-up` and `make lab-bootstrap`.

## License

MIT. See [LICENSE](LICENSE).

## Maintainer

Liam Carvajal · [@LiamCarPer](https://github.com/LiamCarPer)
