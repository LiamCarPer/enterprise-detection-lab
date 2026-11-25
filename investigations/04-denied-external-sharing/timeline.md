# Timeline — INV-004

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-20T14:05:00Z | External-sharing request REQ0007001 denied by the data owner | servicenow-approval | e1 |
| 2026-11-20T14:40:00Z | Customer dataset delivered to partner@example.org | exchange-message-trace | e2 |
| 2026-11-20T14:42:00Z | High-severity DLP alert matched the delivered message | m365-dlp | e3 |

## Correlation notes

- The approval record resolves `mailbox` to `analyst@example.test` and `delivery_recipient` to `partner@example.org`.
- The delivery resolves `mailbox` to the internal related recipient `analyst@example.test` and `delivery_recipient` to the external recipient.
- The approval, delivery, and DLP alert share the message identifier `<20261120144000.701@example.org>`.
- The DLP alert is active and high severity, and the policy is `Customer identifier protection`.
- A later approval for the same content is not present in the evidence.
