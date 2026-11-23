# False-Positive Tuning: Encoded PowerShell

## Summary

`DET-END-001` was tuned after evaluating it against a 20-event synthetic endpoint baseline. The initial query matched eight benign events from an approved endpoint management agent. The tuned query excludes that documented parent process and matches none of the baseline events while preserving all positive fixtures.

| Version | Baseline events | Matches | False-positive rate | Positive fixtures |
|---|---:|---:|---:|---:|
| 1.0.0 — initial | 20 | 8 | 0.40 | 5 / 5 |
| 1.1.0 — tuned | 20 | 0 | 0.00 | 5 / 5 |

## Baseline

[`lab/datasets/synthetic/benign-baseline/endpoint.json`](../lab/datasets/synthetic/benign-baseline/endpoint.json) contains 20 synthetic Sysmon process-creation events:

- 8 encoded PowerShell executions from the approved `CorpMgmt` agent
- 5 normal PowerShell commands without encoding
- 3 Office helper processes
- 2 administrative discovery commands
- 2 encoded PowerShell executions from an existing PowerShell parent

The baseline is separate from the detection fixture corpus. Its purpose is to expose plausible benign activity that a broad detection would otherwise flag.

## Tuning change

The initial query already excluded PowerShell and pwsh parents. The tuned query adds a narrow exclusion for the approved management agent:

```json
{
  "term": {
    "process.parent_name": "corpmgmt.exe"
  }
}
```

The before query is preserved in [`queries/opensearch-before.json`](../detections/endpoint/encoded-powershell-non-powershell-parent/queries/opensearch-before.json) for reproducibility. The final query remains in `queries/opensearch.json`.

## Trade-off

The exclusion is based on parent process name. That is operationally simple but spoofable, and a compromised `corpmgmt.exe` would bypass the detection. The detection runbook now requires monitoring the management agent's integrity. The next tuning step is to replace the name exclusion with a signed-binary or file-hash condition when that telemetry is available.

## Reproduce

```bash
make lab-up
make lab-bootstrap

# Before tuning
edl detection baseline \
  --id DET-END-001 \
  --dataset lab/datasets/synthetic/benign-baseline/endpoint.json \
  --query queries/opensearch-before.json

# After tuning
edl detection baseline \
  --id DET-END-001 \
  --dataset lab/datasets/synthetic/benign-baseline/endpoint.json
```

The lab test [`tests/lab/test_benign_baseline.py`](../tests/lab/test_benign_baseline.py) asserts the same before/after counts in CI.

## Limitations

- The baseline is synthetic and covers one management agent; it is not a production benign corpus.
- The measurement covers one endpoint detection, not the full detection set.
- Parent-name matching is weaker than signature or hash validation.
- The baseline does not model management-agent compromise or credential theft.
