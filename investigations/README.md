# Investigations

An investigation here is an evidence-backed case file, not a narrative-only writeup.

Read [`docs/artifact-model.md`](../docs/artifact-model.md) first. The machine-readable contract is [`schemas/investigation.schema.json`](../schemas/investigation.schema.json).

## Layout

```text
investigations/<nn-slug>/
├── meta.yaml
├── README.md
├── timeline.md
├── queries/
├── evidence/
├── response.md
├── lessons.md
└── executive-summary.md
```

The working reference artifact is `investigations/_template`. Use `edl new investigation` to copy it.

## Add an investigation

1. Pick the scenario and a stable slug.
2. Create the directory.
3. Fill `meta.yaml` and validate it against the schema.
4. Write the scenario, scope, and hypothesis in `README.md`.
5. Build the timeline from evidence.
6. Store queries and redacted/synthetic evidence with provenance.
7. Document detection gaps, telemetry gaps, containment, and lessons.
8. Write the executive summary.
9. Link the detections used by ID.
10. Open a PR; CI must be green.

## Evidence rules

- Synthetic or public data only.
- No PII, secrets, production, or customer data.
- Every evidence item has provenance: source, query, timestamp, and a hash where practical.
- Separate observed evidence from inference.
- Large datasets are downloaded by script; never committed.

## Definition of done

- Schema validation passes.
- Timeline, queries, evidence, response, and lessons are present.
- Detections are linked by ID.
- Detection and telemetry gaps are documented.
- Executive summary is present.
- No PII or production data.
- CI is green.
