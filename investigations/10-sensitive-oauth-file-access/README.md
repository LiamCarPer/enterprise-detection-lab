# INV-010 — Sensitive OAuth Grant to Application File Access

## Scenario

A user consents to an external application with `Files.Read.All` and offline access. Fifteen minutes later, the application accesses a finance file in SharePoint and then downloads it.

## Scope

- Identity: Entra audit telemetry
- SaaS: SharePoint file activity
- Investigation window: 2026-11-23 09:45–10:30 UTC
- User: `analyst@example.test`
- Application: `Contoso Files`
- Site: `https://example.sharepoint.com/sites/finance`

## Hypothesis

Consent phishing or an illicit integration may have provided durable access to files without another sign-in prompt.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 10:00 | entra-audit | e1 | User consent to non-approved `Contoso Files` with `Files.Read.All` and `offline_access` |
| 10:15 | m365-audit | e2 | `FileAccessed` by `Contoso Files` on the finance SharePoint site |
| 10:20 | m365-audit | e3 | `FileDownloaded` by `Contoso Files` from the finance site |

## Inference boundary

The observed events are synthetic lab records. The consent record confirms the application, user, scopes, and offline access. The SharePoint records identify the application as the actor, the finance site as the target, and the file operations. The investigation does not observe the token exchange or prove that the same human actor performed the consent. The application is outside the approved inventory and has failed publisher and redirect trust, but publisher intent and the reputation feed's accuracy are not verified.

## Detections linked

- `DET-IDN-010` — sensitive OAuth grant followed by application file access

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the application identity, the application user, and the target resource name.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
