# Timeline — INV-003

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T08:55:00Z | Medium-risk single-factor sign-in for analyst@example.test | entra-signin | e1 |
| 2026-11-01T09:10:00Z | FullAccess self-delegation to executive@example.test | m365-audit | e2 |
| 2026-11-01T09:20:00Z | Mailbox access to executive@example.test\Inbox | m365-audit | e3 |
| 2026-11-01T09:30:00Z | External forwarding rule created on the executive mailbox | m365-audit | e4 |
| 2026-11-01T09:40:00Z | Forwarding rule updated to a second external recipient | m365-audit | e5 |
| 2026-11-01T09:45:00Z | Message redirected from the executive mailbox to collector@example.org | exchange-message-trace | e6 |
| 2026-11-01T09:46:00Z | Message delivered to the external recipient collector@example.org | exchange-message-trace | e7 |

## Correlation notes

- The five identity and mailbox events share the `analyst@example.test` identity.
- The sign-in and mailbox events use `203.0.113.11`.
- The delegation, access, forwarding, and message-trace events target `executive@example.test`.
- The forwarding rule is created and then updated, showing persistent intent across multiple operations.
- Message trace observes the redirect to `collector@example.org` and confirms external delivery.
- Actor attribution remains inferred, and data-loss-prevention or content confirmation remains out of scope.
