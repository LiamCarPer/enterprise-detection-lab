# INV-003 — SaaS Mailbox Takeover to External Forwarding

## Scenario

A medium-risk single-factor sign-in precedes FullAccess self-delegation to an executive mailbox, mailbox access, two external forwarding-rule changes, and an observed external message delivery in the local lab.

## Scope

- Identity: Entra sign-in telemetry
- SaaS: Microsoft 365 Exchange mailbox audit
- SaaS: Exchange Online message trace
- Investigation window: 2026-11-01 08:45–10:00 UTC for mailbox events and 2026-11-01 09:45–09:46 UTC for message-trace evidence
- Mailbox: `executive@example.test`
- Actor: `analyst@example.test`

## Hypothesis

An identity compromise may have been used to grant mailbox access, collect email, and establish durable external forwarding; message trace confirms that mail left the tenant.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 2026-11-01 08:55 | entra-signin | e1 | Medium-risk single-factor sign-in for `analyst@example.test` |
| 2026-11-01 09:10 | m365-audit | e2 | FullAccess self-delegation to `executive@example.test` |
| 2026-11-01 09:20 | m365-audit | e3 | Mailbox access to the executive inbox |
| 2026-11-01 09:30 | m365-audit | e4 | External forwarding rule created |
| 2026-11-01 09:40 | m365-audit | e5 | Forwarding rule updated to a second external recipient |
| 2026-11-01 09:45 | exchange-message-trace | e6 | Message redirected from the executive mailbox to `collector@example.org` |
| 2026-11-01 09:46 | exchange-message-trace | e7 | Message delivered to the external recipient `collector@example.org` |

## Inference boundary

The observed events are synthetic lab records. The mailbox chain is linked by the analyst identity, source IP, target mailbox, and timing. Exchange message trace now observes the redirect and confirms external delivery, so delivery is no longer inferred. The updated rule’s forwarding recipient matches the message-trace delivery recipient. The trace does not prove that a single actor performed every action, and data-loss-prevention or content confirmation remains out of scope.

## Detections linked

- `DET-SAA-001` — external inbox rule mail forwarding
- `DET-SAA-003` — risky sign-in followed by mail forwarding rule
- `DET-SAA-005` — risky sign-in, self-delegation, and mail access
- `DET-SAA-006` — risky sign-in, self-delegation, mail access, and external forwarding
- `DET-SAA-007` — forwarding rule followed by external delivery

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the executive mailbox, the related recipient, and the source IP.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
