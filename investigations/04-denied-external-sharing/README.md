# INV-004 — Denied Data-Sharing Exception to External Delivery

## Scenario

A user requests approval to send a customer dataset to an external partner. The data owner denies the request. Thirty-five minutes later, the user delivers the dataset to that partner, and a high-severity DLP alert matches the delivered message.

## Scope

- SaaS: ServiceNow approval decision
- SaaS: Exchange Online message trace
- SaaS: Microsoft Purview DLP
- Investigation window: 2026-11-20 13:45–15:15 UTC
- Mailbox: `analyst@example.test`
- External recipient: `partner@example.org`
- Approval request: `REQ0007001`

## Hypothesis

A denied external-sharing decision followed by delivery to the same recipient and a DLP match indicates that the data-handling decision was bypassed.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 2026-11-20 14:05 | servicenow-approval | e1 | External-sharing request `REQ0007001` denied by the data owner |
| 2026-11-20 14:40 | exchange-message-trace | e2 | Customer dataset delivered to `partner@example.org` |
| 2026-11-20 14:42 | m365-dlp | e3 | High-severity DLP alert for the delivered message |

## Inference boundary

The observed events are synthetic lab records. The approval record shows a denial for the same mailbox, recipient, and message identifier that appear in the delivery. The DLP alert confirms a sensitive-content policy match on that message. The evidence does not show whether the requester read the denial or whether a later approval covered the same content; those questions require the approval workflow and the data owner.

## Detections linked

- `DET-SAA-008` — external delivery confirmed by DLP alert
- `DET-SAA-009` — denied exception followed by DLP-confirmed external delivery

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the message identifier, mailbox, external recipient, and analyst user.

## Evidence handling

Each event is stored as a synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
