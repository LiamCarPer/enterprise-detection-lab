# INV-005 — OAuth Consent Grant to External Application

## Scenario

A medium-risk single-factor sign-in is followed by user consent to an external application with mail and offline-access scopes. The application then reads an executive mailbox.

## Scope

- Identity: Entra sign-in and audit telemetry
- SaaS: Microsoft 365 Exchange mailbox audit
- Investigation window: 2026-11-01 08:45–09:30 UTC
- User: `analyst@example.test`
- Application: `Contoso Analytics`
- Mailbox: `executive@example.test`

## Hypothesis

Consent phishing or an illicit application grant may have provided durable access to mail without a second sign-in prompt.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 08:55 | entra-signin | e1 | Medium-risk single-factor sign-in for `analyst@example.test` |
| 09:05 | entra-audit | e2 | User consent to `Contoso Analytics` with `Mail.Read` and `offline_access` |
| 09:22 | m365-audit | e3 | `Contoso Analytics` accessed the executive mailbox |

## Inference boundary

The observed events are synthetic lab records. The consent record confirms the application, user, scopes, and offline access. The mailbox audit record identifies the application as the actor and the executive mailbox as the target. The investigation does not observe the token exchange or prove that the same human actor performed the sign-in and the consent. Publisher intent and redirect-URI safety are not verified.

## Detections linked

- `DET-IDN-001` — successful risky sign-in with single-factor authentication
- `DET-IDN-004` — risky sign-in followed by OAuth consent grant

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the analyst user, the application name, the application resource name, and the executive mailbox.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
