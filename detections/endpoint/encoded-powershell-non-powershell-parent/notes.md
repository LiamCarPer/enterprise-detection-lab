# Detection Notes — DET-END-001

## Hypothesis

PowerShell is a common execution and discovery tool. An encoded command is more suspicious when the parent is not already a PowerShell host, because interactive or nested PowerShell naturally has a PowerShell parent.

## Query design

- `source = sysmon` and `event_code = 1` restrict the query to process creation.
- `process.name` matches `powershell.exe` and `pwsh.exe` using the normalized lowercase basename.
- `match_phrase` on `process.command_line` matches the analyzed `EncodedCommand` token case-insensitively.
- `must_not` excludes PowerShell and pwsh parents to reduce nested-shell noise.
- v1.1.0 also excludes `corpmgmt.exe`, an approved endpoint management agent that generated eight benign encoded-command events in the baseline.

The Sigma rule uses raw Sysmon image and command-line fields. The native OpenSearch query uses canonical fields and is the executed path.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Cover encoded PowerShell from non-PowerShell parents |
| 1.1.0 | Exclude `corpmgmt.exe` parent | Remove eight approved management-agent events from the benign baseline |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positives across cmd, Explorer, Office, service, and script-host parents.
- 5 negatives covering PowerShell parents, non-encoded commands, non-PowerShell images, and unrelated command text.
- 5 benign administrative and user workflows.

The committed metrics are from local fixture replay, not production traffic.

A separate 20-event endpoint benchmark is stored at `lab/datasets/synthetic/benign-baseline/endpoint.json`. The initial query matched 8 management-agent events; the tuned query matches none. The before/after analysis is documented in `reports/false-positive-tuning.md`.

## Known gaps

- Encoded commands from the approved management agent are excluded by parent name; parent names can be spoofed.
- A compromised `corpmgmt.exe` would bypass this detection and requires separate integrity monitoring.
- The query does not decode or score the command content.
- PowerShell logging and script-block telemetry are not correlated.
- Short aliases such as `-enc` without the full token are not matched by the current phrase query.

## Next tuning step

Add script-block and process-access correlation, then replace the parent-name exclusion with a signature or file-hash check for the management agent. Consider a broader encoded-command parser after the detection lifecycle has real benign data.
