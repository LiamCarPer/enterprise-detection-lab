# INV-007 — Interactive Session Reused From a New IP

## Scenario

A successful interactive MFA sign-in is followed by a non-interactive high-risk sign-in that reuses the same session ID from a different source IP.

## Scope

- Identity: Entra sign-in telemetry
- Investigation window: 2026-11-01 08:45–09:30 UTC
- User: `analyst@example.test`
- Session: `session-20261101-09`

## Hypothesis

A session established by MFA may have been replayed from a different network context.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 09:05 | entra-signin | e1 | Interactive MFA sign-in from `198.51.100.23` |
| 09:20 | entra-signin | e2 | Non-interactive high-risk sign-in with the same session from `198.51.100.99` |

## Inference boundary

The observed events are synthetic lab records. The session ID is the direct link between the two sign-ins. The source IP changed, but a VPN, mobile transition, or proxy could explain it. The non-interactive sign-in is high risk, which raises confidence. No downstream mail, file, or cloud action is observed in this evidence.

## Detections linked

- `DET-IDN-001` — successful risky sign-in with single-factor authentication
- `DET-IDN-006` — interactive session reused from a new IP

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the session ID, and the second source IP.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
