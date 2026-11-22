# CLI

The `edl` CLI is the repository’s control surface for validation and the local lab.

## Install

```bash
uv sync --all-extras
```

## Validation

```bash
edl validate
edl validate --path detections/identity/oauth-consent
edl validate --strict
edl validate --sigma
edl validate --json
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Validation passed |
| 1 | Validation failed |
| 2 | Validation could not run |

`--strict` promotes warnings to errors. `--sigma` requires the `sigma` CLI
(`sigma-cli`) and runs `sigma check` on each detection rule.

## Reports

```bash
edl report
edl report --format json
edl report --format markdown
```

The JSON report is designed to be machine-readable and follows
`schemas/validation-report.schema.json`.

## Telemetry matrix

```bash
edl telemetry matrix
edl telemetry matrix --check
edl telemetry matrix --output docs/telemetry-matrix.md
```

`--check` fails when the committed matrix is stale relative to
`telemetry/sources/*.yaml`.

## Scaffolding

```bash
edl new detection --domain identity --slug oauth-consent --id DET-IDN-001 --title "OAuth consent grant"
edl new investigation --slug identity-to-cloud --id INV-001 --title "Identity to cloud"
edl new detection --domain identity --slug test --id DET-IDN-999 --title "Test" --dry-run
```

The generated artifact is a valid copy of the working reference template. Edit
the reference behavior before changing status from `draft` to `tested`.

## Lab

```bash
edl lab up
edl lab status
edl lab wait --timeout 180
edl lab bootstrap
edl lab logs opensearch
edl lab down
edl lab reset --yes
```

`edl lab reset` deletes the named volumes and requires `--yes`.
