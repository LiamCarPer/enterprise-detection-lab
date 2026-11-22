# Capability Matrix

This matrix maps the capabilities that top-tier detection and security engineering teams hire for to concrete artifacts in this repository. It is both a portfolio index and an honest status board.

The matrix is a contract: a capability is only **Complete** when the artifact exists, can be inspected, and has evidence.

---

## How to read this

- **Capability** — the hiring signal.
- **What strong evidence looks like** — the bar, not a keyword.
- **Artifacts** — where the evidence lives or will live.
- **Status** — Foundation, Planned, In progress, Complete.
- **Target level** — Mid, Senior, or Staff-potential.

The target is **senior-level ownership evidence** for mid-level roles at top-tier product companies and senior roles at enterprises. Staff-level is a design target, not a claim.

---

## Matrix

| Capability | What strong evidence looks like | Artifacts | Status | Target level |
|---|---|---|---|---|
| **Adversary understanding** | Threat hypotheses, ATT&CK mapping, attack chains, evasion paths, and investigations that explain what the adversary did and why it matters | `investigations/`, `docs/threat-model.md`, detection metadata | Planned | Mid / Senior |
| **Telemetry expertise** | Identity, endpoint, cloud, SaaS, network, and Kubernetes telemetry; event-time vs ingest-time; schema, quality, gaps, retention, and cost | `telemetry/sources/`, `docs/telemetry-matrix.md`, `lab/`, normalization tests | In progress | Mid / Senior |
| **Detection engineering** | 15–20 deep detections with hypothesis, telemetry contract, Sigma/native query, positive/negative fixtures, replay, benign baseline, false-positive analysis, ATT&CK mapping, runbook, and metrics | `detections/`, `docs/detection-lifecycle.md`, `docs/testing-guide.md`, reports | Planned | Mid / Senior |
| **Software engineering** | Python/Go tooling, APIs, tests, CI/CD, reusable modules, observability, maintainability | `automation/`, `.github/workflows/`, `lab/`, tests | In progress | Mid / Senior |
| **Response engineering** | Investigation automation, evidence capture, containment proposals, approval gates, and effect verification | `automation/`, `investigations/`, runbooks | Planned | Senior |
| **Technical ownership** | Design memo, detection standards, operating model, SLOs, cost model, rollout/rollback, non-goals, and trade-offs | `DESIGN.md`, `docs/detection-standards.md`, `docs/operating-model.md`, `docs/cost-model.md` | Planned | Senior / Staff-potential |
| **Communication** | Clear README, diagrams, investigation writeups, blog posts, talks, and hiring-manager navigation | `README.md`, `INVESTIGATIONS.md`, `docs/blog/`, `docs/talks/` | In progress | Mid / Senior |
| **Collaboration** | One meaningful open-source contribution, code review, issue responses, and practitioner feedback | External PRs, `CONTRIBUTING.md`, feedback notes | Planned | Senior |
| **AI/LLM enhancement** | AI-assisted investigation summaries, agent telemetry detections, and human approval — as an enhancement, not the foundation | `automation/ai/`, optional `detections/agent/`, docs | Optional | Senior / Staff-potential |

---

## Level mapping

| Level | What this repository should prove | Current status |
|---|---|---|
| **Mid** | Can write, test, tune, and investigate detections across multiple telemetry sources; can code useful automation; can communicate clearly | In progress |
| **Senior** | Owns the full detection lifecycle; works across enterprise telemetry; builds production-grade tooling; measures quality; writes design docs and standards; mentors and communicates across teams | Planned |
| **Staff** | Sets architecture across teams; defines org-wide standards; drives adoption; influences strategy | Not claimed. The repo can show potential, not org-wide impact. |

---

## Current evidence

| Artifact | Status | What it proves |
|---|---|---|
| `README.md` | Complete | Problem framing, scope, principles, evaluation paths, honesty about status |
| `docs/capability-matrix.md` | Complete | Understanding of the capability bar and where the evidence will live |
| `docs/requirements-traceability.md` | Complete | Understanding of job requirements and artifact mapping |
| `compose.yaml` + `lab/` | Complete | Local OpenSearch, Dashboards, Kusto, and DuckDB lab skeleton with pinned versions and bootstrap |
| `src/edl/` | Complete | Artifact discovery, schema/required-file validation, telemetry matrix, reports, and lab lifecycle |
| `telemetry/sources/` + `docs/telemetry-matrix.md` | Complete | 11 telemetry source contracts, five sampled, with generated matrix and freshness check |
| Public repository | Complete | Willingness to build in public and be inspected |

---

## Next evidence

The local lab skeleton is healthy. The next milestone is the three-domain core. It will add:

- Telemetry ingestion for identity, endpoint, and cloud sources.
- Six deep detections across the three domains.
- Two enterprise investigations.
- CI/CD, replay, benign baseline, and metrics.
- A first honest results report, including limitations.

After that, the portfolio expands to 15–20 detections, 5–7 investigations, SaaS and network telemetry, automation, and the senior-level design and ownership artifacts.

---

## What would make this matrix credible

- Every **Complete** artifact exists and can be inspected.
- Detections have tests, replay, benign baselines, and metrics.
- Investigations have timelines, queries, evidence, response notes, and lessons learned.
- Metrics are reported with confidence intervals and limitations.
- Design documents include alternatives, non-goals, and trade-offs.
- At least one external contribution or practitioner review exists.

## What would make it not credible

- Capabilities mapped to keywords without artifacts.
- Rules without tests or investigations.
- Metrics without a labeled corpus or benign baseline.
- A large platform with no evidence of doing the job.
- Claims of staff-level impact from a solo repository.
- Copy-pasted rules or AI-generated breadth without verification.

This matrix will be updated as the evidence lands. Until then, **Planned** means planned.
