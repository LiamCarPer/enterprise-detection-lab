# Artifact Model

This repository treats detections and investigations as versioned artifacts, not ad-hoc rules or notes. Every artifact has a predictable layout, machine-readable metadata, tests, evidence, and a definition of done.

The goal is simple: a reviewer can inspect one directory and understand what it detects, why it exists, what telemetry it needs, how it was tested, what it misses, and how to investigate it.

---

## Detection package

Path: `detections/<domain>/<slug>/`

Required files:

```text
detections/<domain>/<slug>/
├── meta.yaml            # machine-readable metadata, validated by schemas/detection.schema.json
├── rule.sigma.yml       # vendor-neutral Sigma rule
├── queries/             # at least one native backend query
│   ├── opensearch.json  # OpenSearch DSL
│   ├── sentinel.kql     # optional in Gate 1, required when KQL support lands
│   └── splunk.spl       # optional
├── fixtures/
│   ├── positive.json    # event(s) that must match
│   ├── negative.json    # event(s) that must not match
│   └── benign.json      # benign activity that must not match
├── tests/
│   ├── test_sigma.py
│   ├── test_opensearch.py
│   └── test_kql.py      # when KQL support lands
├── runbook.md           # triage, evidence, escalation, containment
├── metrics.json         # measured precision/recall/FP/latency for this detection
└── notes.md             # tuning history, known gaps, references
```

The working reference artifact is [`detections/endpoint/_template`](../detections/endpoint/_template). Use `edl new detection` to copy it.

Fixtures are validated by [`schemas/fixture.schema.json`](../schemas/fixture.schema.json). Metrics are validated by [`schemas/metrics.schema.json`](../schemas/metrics.schema.json).

### `meta.yaml`

Validated by [`schemas/detection.schema.json`](../schemas/detection.schema.json). Required fields include:

- stable detection ID
- title, version, status, domain, severity
- hypothesis
- owner
- ATT&CK mapping
- telemetry contract
- query references
- test counts
- false positives
- runbook path

### Detection IDs

`DET-<DOMAIN>-<NNN>`

Domain codes:

| Code | Domain |
|---|---|
| `IDN` | Identity |
| `END` | Endpoint |
| `CLD` | Cloud |
| `SAA` | SaaS |
| `NET` | Network |
| `K8S` | Kubernetes |
| `AGT` | AI agent |

Example: `DET-IDN-001`.

### Status lifecycle

| Status | Meaning |
|---|---|
| `draft` | Metadata exists; rule/tests may be incomplete. |
| `tested` | Positive, negative, and benign fixtures pass locally. |
| `production` | Tested, reviewed, CI green, metrics recorded, runbook present. |
| `retired` | No longer deployed; reason and replacement documented. |

A detection is not `production` just because it compiles. It must have evidence.

### Definition of done

A detection is done when:

- `meta.yaml` validates against the schema.
- The Sigma rule and at least one native query exist.
- Positive, negative, and benign fixtures exist and pass.
- False-positive analysis and tuning notes exist.
- The runbook covers triage, evidence, escalation, and containment.
- Metrics are recorded: precision, recall, false-positive rate, latency, and limitations.
- README/status tables are updated.
- CI is green.

---

## Investigation package

Path: `investigations/<nn-slug>/`

Required files:

```text
investigations/01-identity-to-cloud/
├── meta.yaml            # structured metadata, validated by schemas/investigation.schema.json
├── README.md            # scenario, scope, hypothesis, summary
├── timeline.md          # ordered events with timestamps and sources
├── queries/             # queries used during the investigation
├── evidence/            # redacted/synthetic evidence, hashes, provenance
├── response.md          # containment, eradication, recovery, verification
├── lessons.md           # detection gaps, tuning, telemetry gaps
└── executive-summary.md # customer/executive-ready summary
```

### Investigation IDs

`INV-<NNN>`

Example: `INV-001`.

### Status lifecycle

| Status | Meaning |
|---|---|
| `draft` | Scenario and notes exist; evidence may be incomplete. |
| `tested` | Timeline, evidence, queries, and response are complete enough for review. |
| `published` | Reviewed, evidence-backed, linked detections, and executive summary present. |
| `retired` | Superseded or no longer representative; reason documented. |

### Evidence rules

- Use synthetic or public data only.
- No PII, secrets, real employer data, or customer data.
- Every evidence item has provenance: source, query, timestamp, and a hash where practical.
- Raw evidence is stored as a small, redacted fixture; large datasets are downloaded by script and never committed.
- The investigation must distinguish observed evidence from inference.

### Definition of done

An investigation is done when:

- `meta.yaml` validates against the schema.
- Timeline, queries, evidence, response, and lessons are present.
- Every detection used in the investigation is linked by ID.
- Detection gaps and telemetry gaps are documented.
- An executive summary is present and free of jargon where possible.
- No PII or real employer data is present.
- README/status tables are updated.
- CI is green.

---

## Naming and versioning

- Directory slugs: lowercase, hyphen-separated, stable.
- Detection versions: semver (`1.0.0`).
- Investigation versions: semver (`1.0.0`).
- Query filenames: `opensearch.json`, `sentinel.kql`, `splunk.spl`, `sigma.yml`.
- Fixture names: `positive.json`, `negative.json`, `benign.json`.
- Do not rename an artifact ID after publication; create a new version or a retired note instead.

---

## Data and safety rules

- No secrets, credentials, tokens, PII, or real employer/customer data.
- No malware or destructive payloads.
- Public datasets must include a license and provenance note.
- Large datasets are downloaded by script; never commit raw datasets.
- Attack simulation runs in an isolated lab and follows the repository's safety notes.
- Do not commit job-search notes, CV strategy, or target-company research.

---

## Review checklist

- [ ] Schema validation passes.
- [ ] Tests pass locally and in CI.
- [ ] Positive, negative, and benign fixtures are present.
- [ ] False positives and limitations are documented.
- [ ] Runbook or investigation response is actionable.
- [ ] Metrics are recorded and reproducible.
- [ ] No secrets, PII, or real employer data.
- [ ] README/status tables are updated.
- [ ] Commit is atomic and push-worthy.
