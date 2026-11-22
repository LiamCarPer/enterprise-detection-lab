# Detections

A detection here is a versioned package, not a single Sigma file.

Read [`docs/artifact-model.md`](../docs/artifact-model.md) first. The machine-readable contract is [`schemas/detection.schema.json`](../schemas/detection.schema.json).

## Layout

```text
detections/<domain>/<slug>/
├── meta.yaml
├── rule.sigma.yml
├── queries/
│   ├── opensearch.kql
│   ├── sentinel.kql
│   └── splunk.spl
├── fixtures/
│   ├── positive.json
│   ├── negative.json
│   └── benign.json
├── tests/
├── runbook.md
├── metrics.json
└── notes.md
```

## Add a detection

1. Pick the domain and a stable slug.
2. Create the directory.
3. Copy the detection template when it lands.
4. Fill `meta.yaml` and validate it against the schema.
5. Add the Sigma rule and at least one native query.
6. Add positive, negative, and benign fixtures.
7. Add tests and make them pass.
8. Write the runbook and tuning notes.
9. Record metrics and limitations.
10. Update the README/status tables.
11. Open a PR; CI must be green.

## Definition of done

- Schema validation passes.
- Sigma and native query exist.
- Positive, negative, and benign fixtures pass.
- False positives and tuning notes are documented.
- Runbook covers triage, evidence, escalation, and containment.
- Metrics are recorded.
- CI is green.
- No secrets, PII, or real employer data.

A detection is not done because it compiles. It is done when it has evidence.
