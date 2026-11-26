# INV-008 — Interactive Sign-In Followed by Risky Sign-In From a New Country

## Scenario

A successful interactive MFA sign-in from the United States is followed by a non-interactive high-risk sign-in from the Netherlands within 15 minutes.

## Scope

- Identity: Entra sign-in telemetry
- Investigation window: 2026-11-01 09:45–10:30 UTC
- User: `analyst@example.test`
- Countries: `US` → `NL`

## Hypothesis

The user's session or credentials may have been used from an impossible location.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 10:00 | entra-signin | e1 | Interactive MFA sign-in from the United States |
| 10:15 | entra-signin | e2 | Non-interactive high-risk sign-in from the Netherlands |

## Inference boundary

The observed events are synthetic lab records. The country change is direct evidence, and the second sign-in is high risk. The investigation does not calculate travel distance or speed, and it does not observe downstream mail, file, or cloud activity. A VPN or proxy could explain the country change.

## Detections linked

- `DET-IDN-001` — successful risky sign-in with single-factor authentication
- `DET-IDN-007` — interactive sign-in followed by risky sign-in from a new country

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the two countries, and the second source IP.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
