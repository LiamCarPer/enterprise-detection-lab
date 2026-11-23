# Detection Notes — DET-END-002

## Hypothesis

Office applications normally spawn helpers such as printing, preview, and update processes. Spawning a scripting or command interpreter is a high-value deviation that can indicate a malicious document or compromised add-in.

## Query design

- `source = sysmon` and `event_code = 1` restrict the query to process creation.
- `process.parent_name` matches normalized lowercase Office executable names.
- `process.name` matches PowerShell, pwsh, cmd, Windows Script Host, cscript, and mshta.
- Basenames are normalized by the Sysmon normalizer, so Windows path case and directory differences do not affect the query.

The Sigma rule uses raw Sysmon image fields. The native OpenSearch query uses canonical fields and is the executed path.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Cover Office-to-scripting-host execution |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positives across Word, Excel, Outlook, PowerPoint, and Access.
- 5 negatives with non-Office parents, non-scripting children, and Office processes launched by Explorer.
- 5 benign Office helper processes.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- Office add-ins and approved macros can produce the same behavior.
- Document path, hash, and email context are not part of the query.
- The query does not distinguish signed or trusted add-ins.
- Other interpreters such as Python or wsl.exe are not included.

## Next tuning step

Add document path and hash enrichment, then correlate with email delivery and file creation. Expand the child interpreter list only after reviewing benign Office behavior in the lab.
