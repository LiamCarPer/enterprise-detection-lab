# Timeline — INV-002

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T09:18:00Z | Encoded PowerShell executed on LAB-EP-01 | sysmon | e1 |
| 2026-11-01T09:22:00Z | Failed network logon from 198.51.100.23 | windows-security | e2 |
| 2026-11-01T09:25:00Z | IAM access key created for analyst | aws-cloudtrail | e3 |
| 2026-11-01T09:30:00Z | CloudTrail logging stopped on lab-trail | aws-cloudtrail | e4 |

## Correlation notes

- The Sysmon and Windows Security events share `LAB-EP-01`.
- The failed logon follows the encoded PowerShell execution by four minutes.
- The cloud events use the `analyst` identity and documentation IP ranges.
- No shared process identifier or cloud session links the endpoint and cloud events. That link is inferred.
