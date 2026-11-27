# Timeline — INV-005

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T08:55:00Z | Medium-risk single-factor sign-in for analyst@example.test | entra-signin | e1 |
| 2026-11-01T09:05:00Z | User consent to non-approved Contoso Analytics with Mail.Read, offline_access, and failed publisher and redirect trust | entra-audit | e2 |
| 2026-11-01T09:22:00Z | Contoso Analytics accessed the executive mailbox | m365-audit | e3 |

## Correlation notes

- The sign-in and consent share the `analyst@example.test` user.
- The consent target is the `Contoso Analytics` service principal, owned by an external organization.
- The application access event names `Contoso Analytics` as the user and `executive@example.test` as the mailbox.
- The consent includes `Mail.Read` and `offline_access`, which supports durable mail access.
- No token exchange event is observed; the application access is the closest available impact evidence.
