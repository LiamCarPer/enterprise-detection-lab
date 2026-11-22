# Enterprise Detection Engineering Lab

**Production-like detection engineering for identity, endpoint, cloud, SaaS, and network telemetry — engineered like software.**

**Status:** foundation. Built in public. The first milestone is the three-domain core: identity, endpoint, and cloud, with six deep detections, two investigations, CI, and metrics.

[Capability matrix](docs/capability-matrix.md) · [Requirements traceability](docs/requirements-traceability.md) · [Artifact model](docs/artifact-model.md)

---

## Why this repo exists

Most detection portfolios are collections of Sigma rules, screenshots, and SIEM queries. High-performing detection teams treat detections as production software: they own the telemetry contract, test against adversary and benign behavior, ship through CI/CD, measure precision and coverage, and investigate the result end to end.

This repo is a working lab for that discipline.

It is:

- a portfolio for detection engineering, security engineering D&R, security automation, and cloud detection roles;
- a reproducible lab for identity, endpoint, cloud, SaaS, network, and Kubernetes telemetry;
- a place to document design decisions, trade-offs, and limitations.

It is not:

- a SIEM product;
- a SOC tutorial or home-lab screenshot collection;
- an OT/ICS lab;
- an AI SOC wrapper;
- a research paper;
- a staff-level platform.

---

## What this demonstrates

The target portfolio is deliberately depth-first:

| Area | Target | Current status |
|---|---|---|
| Identity detections | 4–5 deep detections across Entra ID / AD / Okta-like flows | Planned |
| Endpoint detections | 4–5 deep detections across Windows/Sysmon and Linux | Planned |
| Cloud detections | 4–5 deep detections across AWS, Azure, and GCP audit logs | Planned |
| SaaS detections | 2–3 deep detections across M365, GitHub, and Salesforce-like logs | Planned |
| Network detections | 2–3 deep detections across Zeek, Suricata, DNS, proxy, and firewall | Planned |
| Investigations | 5–7 enterprise attack chains with evidence and response notes | Planned |
| Local lab | Reproducible Docker Compose lab with identity, endpoint, and cloud telemetry | Planned |
| CI/CD | Lint, tests, conversion, replay, staged deployment, rollback, metrics | Planned |
| Automation | Enrichment, triage, evidence capture, containment proposals, approval gates | Planned |
| Design and ownership | Design memo, detection standards, operating model, cost model | Planned |
| External validation | One meaningful open-source contribution, one blog post, one talk | Planned |

### Current foundation

- [x] Repository renamed and public
- [x] README
- [x] Capability matrix
- [x] Requirements traceability matrix
- [x] Detection and investigation artifact contracts
- [ ] Three-domain lab
- [ ] First six deep detections
- [ ] First two investigations
- [ ] CI/CD and metrics
- [ ] Expanded portfolio
- [ ] Automation
- [ ] Design memo and standards
- [ ] Open-source contribution, blog, and talk

Artifacts marked **Planned** do not exist yet. The status will be updated as each artifact lands. The intent is to make the repo honest and inspectable at every stage, not to present a finished product.

---

## How to evaluate this repo

A hiring manager should be able to evaluate it in layers:

**5 minutes**

- Read this README.
- Read the [capability matrix](docs/capability-matrix.md).
- Check the current status table above.

**15 minutes**

- Read the [requirements traceability matrix](docs/requirements-traceability.md).
- Inspect the first available detections and investigations.
- Check whether tests, replay, and metrics actually exist.

**30 minutes**

- Read the design memo and detection standards.
- Walk through one detection lifecycle end to end.
- Ask: “Show me a detection that failed. How did you find it, diagnose it, and fix it?”

The questions I want to be asked are:

- Show me a detection lifecycle, from hypothesis to retirement.
- Show me how you test a detection against adversary behavior and a benign baseline.
- Show me a detection that failed or was noisy. What did you change?
- Show me an investigation across identity, endpoint, and cloud.
- Show me how you measure detection quality.
- Show me a trade-off you made and what you chose not to build.

---

## Design principles

1. **Depth over count.** Ten deep detections with tests and investigations beat one hundred shallow rules.
2. **Detection-as-code.** Every detection is versioned, reviewed, tested, and deployed through CI.
3. **Telemetry contracts.** Every detection states its source, fields, timing, quality assumptions, and failure modes.
4. **Replay both sides.** Every detection is tested against adversary behavior and a benign baseline.
5. **Measure quality.** Precision, recall, false positives, coverage, latency, and cost are first-class outputs.
6. **Automate safely.** Enrichment, triage, evidence, and containment proposals are code; high-impact actions require human approval.
7. **Document judgment.** Design memos, non-goals, trade-offs, and limitations are part of the artifact.
8. **General enterprise.** No OT in this repo; OT experience stays in the interview narrative as a differentiator.

---

## Scope and target roles

### In scope

- **Identity:** Entra ID, Active Directory, Okta-like flows.
- **Endpoint:** Windows/Sysmon, Linux audit, EDR-like telemetry.
- **Cloud:** AWS CloudTrail/IAM, Azure activity, GCP audit.
- **SaaS:** M365, GitHub, Salesforce, Slack/Okta audit logs.
- **Network:** Zeek, Suricata, DNS, proxy, firewall.
- **Kubernetes:** audit logs, Falco, runtime telemetry.

### Out of scope

- OT/ICS telemetry.
- Production deployment or real employer data.
- Commercial EDR/SIEM licenses.
- Autonomous response without human approval.
- A full multi-tenant platform.
- A research paper.

### Target roles

- Mid-level detection engineering / security engineering D&R / security automation at top-tier product companies.
- Senior detection engineering at enterprises as a parallel path.
- Staff-level is a design target, not a claim. The repo can show potential, not org-wide impact.

---

## Repository map

```text
.
├── README.md
├── docs/
│   ├── capability-matrix.md
│   ├── requirements-traceability.md
│   ├── artifact-model.md
│   ├── telemetry-matrix.md          # planned
│   ├── detection-lifecycle.md       # planned
│   ├── testing-guide.md             # planned
│   ├── detection-standards.md       # planned
│   ├── operating-model.md           # planned
│   ├── cost-model.md                # planned
│   ├── threat-model.md              # planned
│   └── blog/                        # planned
├── schemas/                         # JSON schemas for artifact metadata
├── detections/                      # detection packages; see detections/README.md
├── investigations/                  # investigation packages; see investigations/README.md
├── automation/                      # planned
├── lab/                             # planned
├── conformance/                     # planned; optional senior signal
├── console/                         # planned; static report UI
└── .github/workflows/               # planned
```

---

## Roadmap

The roadmap is evidence-gated, not date-driven. Each gate has a definition of done and a kill criterion.

| Gate | Focus | Definition of done |
|---|---|---|
| **0 — Foundation** | Repository, README, matrices | README, capability matrix, and requirements traceability are public and honest. |
| **1 — Core lab** | Identity, endpoint, cloud | Reproducible lab; six deep detections; two investigations; CI; metrics. |
| **2 — Depth** | Enterprise breadth | 15–20 detections; 5–7 investigations; SaaS and network telemetry; automation. |
| **3 — Senior signal** | Ownership and judgment | Design memo, detection standards, operating model, one meaningful open-source contribution, blog, talk. |
| **4 — Application and iteration** | Hiring feedback | Apply to top-tier mid-level and senior enterprise roles; update the repo based on interview feedback. |

Kill criteria:

- If the lab cannot produce stable, reproducible detection results, fix the lab before expanding.
- If a detection cannot be tested against a benign baseline, do not count it as complete.
- If an investigation cannot be explained with evidence, it is a story, not an artifact.
- If the repo becomes a collection of shallow rules, stop and cut scope.

---

## Related work

This lab builds on and integrates with existing open standards and tools:

- [SigmaHQ](https://github.com/SigmaHQ/sigma) and [pySigma](https://github.com/SigmaHQ/pySigma) for vendor-neutral detection rules and conversion.
- [RSigma](https://github.com/timescale/rsigma) for Sigma evaluation, backtesting, and diagnostics.
- [Scythe sigma-regression-testing](https://github.com/scythe-io/sigma-regression-testing) for continuous detection validation and Atomic Red Team mapping.
- [Elastic detection-rules](https://github.com/elastic/detection-rules) and [Splunk contentctl](https://github.com/splunk/contentctl) for detection-as-code testing patterns.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for adversary emulation.
- [OCSF](https://github.com/ocsf/ocsf-schema) for enterprise telemetry normalization.
- [Falco](https://github.com/falcosecurity/falco), [Zeek](https://github.com/zeek/zeek), and [Suricata](https://github.com/OISF/suricata) for runtime and network telemetry.

This is a portfolio lab, not a product. It does not claim novelty for basic detection validation; it demonstrates the engineering discipline around it.

---

## Limitations

- The repository is at the foundation stage. Detections, investigations, lab, metrics, and automation are not yet implemented.
- The lab will use local, synthetic, and public telemetry. It will not represent production scale.
- Measurements will be small. Results will be reported with confidence intervals and explicit limitations.
- No commercial EDR or SIEM licenses. The lab will use open-source/public tooling and a local Kusto emulator where possible.
- No OT/ICS telemetry in this repo.
- No autonomous response. Containment proposals will require human approval.
- This repo is not a substitute for real operational experience.

---

## License

MIT. See [LICENSE](LICENSE).

---

## Contact

**Liam Carvajal** · [@LiamCarPer](https://github.com/LiamCarPer)

Open to detection engineering, security engineering D&R, security automation, and cloud detection roles at top-tier product companies.
