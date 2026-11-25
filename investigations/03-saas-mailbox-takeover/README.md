# INV-003 — SaaS Mailbox Takeover to External Forwarding

## Scenario

A medium-risk single-factor sign-in precedes FullAccess self-delegation to an executive mailbox, mailbox access, and two external forwarding-rule changes in the local lab.

## Scope

- Identity: Entra sign-in telemetry
- SaaS: Microsoft 365 Exchange mailbox audit
- Investigation window: 2026-11-01 08:45–10:00 UTC
- Mailbox: `executive@example.test`
- Actor: `analyst@example.test`

## Hypothesis

An identity compromise may have been used to grant mailbox access, collect email, and establish durable external forwarding while hiding messages from the mailbox owner.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 08:55 | entra-signin | e1 | Medium-risk single-factor sign-in for `analyst@example.test` |
| 09:10 | m365-audit | e2 | FullAccess self-delegation to `executive@example.test` |
| 09:20 | m365-audit | e3 | Mailbox access to the executive inbox |
| 09:30 | m365-audit | e4 | External forwarding rule created |
| 09:40 | m365-audit | e5 | Forwarding rule updated to a second external recipient |

## Inference boundary

The observed events are synthetic lab records. They are linked by the analyst identity, source IP, target mailbox, and timing. The investigation does not observe outbound message delivery or prove that a single actor performed every action. No message-trace or data-loss-prevention telemetry is in scope.

## Detections linked

- `DET-SAA-001` — external inbox rule mail forwarding
- `DET-SAA-003` — risky sign-in followed by mail forwarding rule
- `DET-SAA-005` — risky sign-in, self-delegation, and mail access
- `DET-SAA-006` — risky sign-in, self-delegation, mail access, and external forwarding

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the executive mailbox, and the source IP.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
