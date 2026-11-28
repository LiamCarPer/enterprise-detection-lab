# Timeline — INV-010

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-23T10:00:00Z | User consent to non-approved Contoso Files with Files.Read.All and offline_access | entra-audit | e1 |
| 2026-11-23T10:15:00Z | Contoso Files accessed a finance SharePoint file | m365-audit | e2 |
| 2026-11-23T10:20:00Z | Contoso Files downloaded the finance SharePoint file | m365-audit | e3 |

## Correlation notes

- The consent and file activity share the `contoso files` application identity.
- The consent includes `Files.Read.All` and `offline_access`, which supports durable file access.
- The file activity targets the finance site and the same file path.
- No token exchange event is observed; the SharePoint records are the closest available impact evidence.
