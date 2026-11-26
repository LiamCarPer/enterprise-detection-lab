# Timeline — INV-007

| Timestamp | Event | Source | Evidence |
|---|---|---|---|
| 2026-11-01T09:05:00Z | Interactive MFA sign-in for analyst@example.test from 198.51.100.23 | entra-signin | e1 |
| 2026-11-01T09:20:00Z | Non-interactive high-risk sign-in with the same session from 198.51.100.99 | entra-signin | e2 |

## Correlation notes

- Both events share `session-20261101-09` and the `analyst@example.test` identity.
- The source IP changed from `198.51.100.23` to `198.51.100.99`.
- The second sign-in is non-interactive and high risk.
- No device change, token-protection result, or downstream access is observed.
- A travel, VPN, or mobile-network explanation is not present in the evidence.
