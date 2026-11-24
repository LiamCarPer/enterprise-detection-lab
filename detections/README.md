# Detections

A detection here is a versioned package, not a single Sigma file.

Read [`docs/artifact-model.md`](../docs/artifact-model.md) first. The machine-readable contract is [`schemas/detection.schema.json`](../schemas/detection.schema.json). Approved exceptions are recorded in [`detections/exceptions.yaml`](exceptions.yaml) under the [exception policy](../docs/exception-policy.md).

## Layout

```text
detections/<domain>/<slug>/
├── meta.yaml
├── rule.sigma.yml
├── queries/
│   ├── opensearch.json
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

The working reference artifact is `detections/endpoint/_template`. Use `edl new detection` to copy it. Run `edl detection test --id DET-END-000` to execute the reference query against its normalized fixtures.

## Add a detection

1. Pick the domain and a stable slug.
2. Create the directory.
3. Copy the detection template.
4. Fill `meta.yaml` and validate it against the schema.
5. Add the Sigma rule and at least one native query.
6. Add positive, negative, and benign fixtures.
7. Add tests and run `edl detection test --id <DETECTION_ID>`.
8. Write the runbook and tuning notes.
9. Generate metrics with `edl detection test --id <DETECTION_ID> --write-metrics`.
10. Update the README/status tables.
11. Open a PR; CI must be green.

## Definition of done

- Schema validation passes.
- Sigma and native query exist.
- Positive, negative, and benign fixtures pass in `edl detection test`.
- False positives and tuning notes are documented.
- Runbook covers triage, evidence, escalation, and containment.
- Metrics are generated from fixture replay and include limitations.
- CI is green.
- No secrets, PII, or production data.

A detection is not done because it compiles. It is done when it has evidence.
