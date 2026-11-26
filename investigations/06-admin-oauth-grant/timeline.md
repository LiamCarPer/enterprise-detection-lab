# Timeline — INV-006

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-02T10:00:00Z | Admin consent to Contoso Analytics with failed publisher and redirect trust | entra-audit | e1 |
| 2026-11-02T10:05:00Z | Tenant-wide OAuth2 permission grant to Contoso Analytics | entra-audit | e2 |

## Correlation notes

- Both events were initiated by `admin@example.test`.
- The application owner organization is external to the modeled tenant.
- The consent record fails both publisher verification and redirect-URI trust.
- The second event grants tenant-wide permissions for the same application.
- No downstream application access is observed in this investigation.
