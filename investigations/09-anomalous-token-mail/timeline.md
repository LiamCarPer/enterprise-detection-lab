# Timeline — INV-009

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T09:10:00Z | Anomalous-token sign-in without token protection for analyst@example.test | entra-signin | e1 |
| 2026-11-01T09:20:00Z | MailItemsAccessed on executive@example.test | m365-audit | e2 |

## Correlation notes

- Both events share the `analyst@example.test` identity.
- The sign-in is non-interactive, high risk, and flagged with `anomalousToken`.
- Token protection is `notProtected` and token binding is `unbound`.
- The mailbox access follows within 10 minutes.
- No token exchange, client application, or downstream cloud activity is observed.
