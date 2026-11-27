# INV-006 — Admin Consent and Tenant-Wide OAuth Grant

## Scenario

An administrator grants admin consent to an external application outside the approved inventory with an unverified publisher, untrusted redirect URI, and untrusted publisher reputation. Five minutes later, a tenant-wide OAuth permission grant is recorded for the same application.

## Scope

- Identity: Entra audit telemetry
- SaaS: Application permissions and consent
- Investigation window: 2026-11-02 09:45–10:30 UTC
- Administrator: `admin@example.test`
- Application: `Contoso Analytics`

## Hypothesis

An admin or tenant-wide OAuth grant to an untrusted application may provide durable access to tenant mail, files, or directory data.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 10:00 | entra-audit | e1 | Admin consent to non-approved `Contoso Analytics` with failed publisher and redirect trust and untrusted publisher reputation |
| 10:05 | entra-audit | e2 | Tenant-wide `Add OAuth2PermissionGrant` for `Contoso Analytics` |

## Inference boundary

The observed events are synthetic lab records. The consent and grant records confirm the application, administrator, tenant-wide scope, failed trust checks, and untrusted publisher reputation. The investigation does not observe application access after the grant, and it does not prove the application publisher's intent.

## Detections linked

- `DET-IDN-005` — admin or tenant OAuth grant to an untrusted application

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the administrator, the application resource name, the application owner organization, and the tenant-wide flag.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
