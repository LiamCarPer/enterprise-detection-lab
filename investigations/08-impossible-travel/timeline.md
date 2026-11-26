# Timeline — INV-008

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T10:00:00Z | Interactive MFA sign-in for analyst@example.test from the United States | entra-signin | e1 |
| 2026-11-01T10:15:00Z | Non-interactive high-risk sign-in from the Netherlands | entra-signin | e2 |

## Correlation notes

- Both events share the `analyst@example.test` identity.
- The country changed from `US` to `NL` within 15 minutes.
- The second sign-in is non-interactive and high risk.
- No device, travel, or network-change context is present.
- No downstream mail, file, or cloud action is observed.
