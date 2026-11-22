# Requirements Traceability Matrix

This document maps recurring requirements from top-tier detection engineering and security engineering roles to artifacts in this repository. It is a hiring-manager index: pick a requirement, follow the artifact.

This is not a claim that every requirement is met. It is a traceability contract that shows where the evidence will live and what is currently implemented.

---

## Sources and scope

The requirements are a directional synthesis of public job postings and engineering blogs from top-tier product companies, including:

- Google
- AWS
- Microsoft
- Datadog
- OpenAI
- Palantir
- Cloudflare
- CrowdStrike
- Palo Alto Networks
- SentinelOne

The synthesis is not a statistical sample. Requirements vary by team, level, and location. Verify current postings before applying.

The target is **senior-level ownership evidence** for mid-level roles at top-tier product companies and senior roles at enterprises. Staff-level is a design target, not a claim.

---

## Matrix

| Requirement | What interviewers look for | Repository artifact | Evidence | Status |
|---|---|---|---|---|
| **Detection-as-code** | Rules are versioned, reviewed, tested, converted, deployed, and retired like software | `.github/workflows/`, `detections/`, `docs/detection-lifecycle.md` | CI pipeline, rule metadata, review checklist, rollback plan | Planned |
| **Programming / production engineering** | Python/Go, APIs, tests, reusable modules, maintainability, observability | `automation/`, `lab/`, tests | Working tools with tests, error handling, retries/idempotency, docs | Planned |
| **Detection depth / full lifecycle** | Hypothesis → telemetry → implementation → validation → deployment → tuning → measurement → retirement | `detections/`, `docs/detection-lifecycle.md` | 15–20 deep detections with lifecycle evidence | Planned |
| **Enterprise telemetry breadth** | Identity, endpoint, cloud, SaaS, network, Kubernetes | `docs/telemetry-matrix.md`, `lab/`, detections | Telemetry matrix, mappings, tests, per-domain detections | Planned |
| **Telemetry contracts / schema drift** | Required fields, semantics, timing, quality, versioning, failure modes | `docs/telemetry-matrix.md`, normalization tests, conformance layer | Contract definitions, schema-variant tests, impact reports | Planned |
| **Detection validation / regression** | Replay, attack simulation, synthetic telemetry, unit tests, regression tests | `lab/`, `detections/tests/`, `conformance/` | Positive/negative fixtures, Atomic/Stratus replay, CI results | Planned |
| **Benign baseline / false-positive control** | Measures noise against realistic benign activity, not an idle lab | `lab/`, `detections/tests/`, reports | Generated benign workload, false-positive rate, tuning notes | Planned |
| **Detection quality metrics** | Precision, recall, false positives, coverage, latency, cost | `reports/`, `docs/operating-model.md` | Metrics report with confidence intervals and limitations | Planned |
| **Incident response / investigation** | Timeline, evidence, scope, containment, lessons learned | `investigations/`, runbooks | 5–7 enterprise investigations with evidence | Planned |
| **Automation / security tooling** | Enrichment, triage, evidence capture, containment proposals, approvals | `automation/` | Tools with tests, API integrations, approval gates, effect verification | Planned |
| **Threat modeling / adversary understanding** | Attacker TTPs, attack paths, evasion, telemetry implications | `docs/threat-model.md`, `investigations/` | Threat model, ATT&CK mapping, adversary-driven hypotheses | Planned |
| **Communication / ownership** | Design docs, investigation writeups, cross-team communication, mentoring | `README.md`, `DESIGN.md`, `INVESTIGATIONS.md`, `docs/blog/`, `docs/talks/` | Clear writing, diagrams, blog, talk, review checklist | In progress |
| **Collaboration / open source** | Works with maintainers, code review, external validation | External contributions, `CONTRIBUTING.md` | One meaningful merged contribution, feedback notes | Planned |
| **AI/LLM enhancement** | AI-assisted investigation, agent telemetry, human approval, not autonomous response | `automation/ai/`, optional `detections/agent/` | Grounded summaries, human approval, evaluation notes | Optional |
| **Cloud/identity depth** | Entra/AD/Okta, AWS/Azure/GCP audit, IAM, token/session abuse | `detections/identity/`, `detections/cloud/`, `investigations/` | Identity/cloud detections and attack chains | Planned |

---

## Company emphasis

| Company type | Examples | What they emphasize | Repository evidence |
|---|---|---|---|
| **Hyperscalers / big tech** | Google, AWS, Microsoft, Apple, Meta, Cloudflare, OpenAI, Anthropic | Coding, detection engineering, threat modeling, regression testing, incident response, telemetry breadth | Detections, CI, investigations, automation, design memo |
| **Security vendors** | CrowdStrike, Palo Alto Networks, SentinelOne, Datadog, Elastic, Splunk/Cisco | Detection depth, endpoint/cloud telemetry, rule lifecycle, testing, precision/coverage | Deep detections, replay, benign baseline, metrics, backend translation |
| **Enterprises (parallel path)** | Banks, insurers, healthcare, manufacturing | Full lifecycle ownership, enterprise breadth, metrics, design judgment, communication | Design memo, standards, operating model, investigations |

---

## Coverage summary

| Metric | Current |
|---|---|
| Requirements mapped | 15 / 15 |
| Foundation artifacts complete | README, capability matrix, requirements traceability |
| Detections implemented | 0 |
| Investigations implemented | 0 |
| Lab implemented | No |
| CI/CD implemented | No |
| Metrics implemented | No |
| Open-source contribution | Not yet |

The mapping is complete. The implementation is not. The next milestone is the three-domain core: identity, endpoint, and cloud, with six deep detections, two investigations, CI, and metrics.

---

## How to use this document

**If you are a hiring manager:**

1. Pick a requirement that matters to your team.
2. Follow the artifact column.
3. If the status is **Planned**, treat it as planned, not done.
4. Ask for a walkthrough of one complete artifact.

**If you are reviewing the portfolio:**

1. Start with the requirements that are most important to the role.
2. Check whether the evidence exists.
3. Look for depth: tests, replay, benign baseline, metrics, investigations, design trade-offs.
4. Look for honesty: limitations, negative results, and what is not built.

**Questions I want to be asked:**

- Show me a detection lifecycle from hypothesis to retirement.
- Show me how you test a detection against adversary behavior and a benign baseline.
- Show me a detection that failed. What did you change?
- Show me an investigation across identity, endpoint, and cloud.
- Show me how you measure detection quality.
- Show me a trade-off you made and what you chose not to build.
- Show me what you would do differently in a real enterprise.

---

## What this matrix is not

- It is not a claim that every requirement is met.
- It is not a keyword checklist.
- It is not a substitute for interviews or real operational experience.
- It is not static. It will be updated as artifacts are implemented, tested, and reviewed.

Until then, **Planned** means planned.
