# INV-009 — Anomalous Token Sign-In to Mail Collection

## Scenario

A non-interactive sign-in with an anomalous-token risk detection and missing token protection is followed by mailbox access for the same user.

## Scope

- Identity: Entra sign-in telemetry
- SaaS: Microsoft 365 Exchange mailbox audit
- Investigation window: 2026-11-01 08:45–09:30 UTC
- User: `analyst@example.test`
- Mailbox: `executive@example.test`

## Hypothesis

A stolen or replayed token may have been used to collect email.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 09:10 | entra-signin | e1 | Non-interactive high-risk sign-in with a long-lived `anomalousToken`, `notProtected`, and `unbound` |
| 09:20 | m365-audit | e2 | `MailItemsAccessed` on the executive mailbox |

## Inference boundary

The observed events are synthetic lab records. The sign-in risk detection and missing token protection are direct evidence. The mailbox access follows within the correlation window. The investigation does not observe the token exchange, the client application that used the token, or the actor's intent. A legitimate client with a risk false positive could explain the sequence.

## Detections linked

- `DET-IDN-008` — anomalous token sign-in followed by mail access

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the anomalous-token risk, the mailbox, and the token-protection state.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
