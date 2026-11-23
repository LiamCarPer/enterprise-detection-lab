# Timeline — INV-001

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T08:55:00Z | Medium-risk single-factor sign-in for analyst@example.test | entra-signin | e1 |
| 2026-11-01T09:10:00Z | Service principal Lab Reporting App created | entra-audit | e2 |
| 2026-11-01T09:12:00Z | Owner added to the new service principal | entra-audit | e3 |
| 2026-11-01T09:25:00Z | IAM access key created for analyst | aws-cloudtrail | e4 |
| 2026-11-01T09:30:00Z | CloudTrail logging stopped on lab-trail | aws-cloudtrail | e5 |

## Correlation notes

- The sign-in and cloud events share the `analyst` identity.
- The audit events were initiated by `admin@example.test`.
- The cloud events originate from documentation IP ranges used by the identity events.
- No explicit role-assumption event connects the identity and cloud sessions. That link is inferred.
