# Detection Notes — DET-IDN-007

## Hypothesis

A user cannot normally complete an interactive MFA sign-in in one country and then sign in from a different country within 30 minutes. A country change with elevated risk can indicate impossible travel or token theft.

## Query and correlation design

The native query returns two kinds of Entra sign-in events:

- successful interactive MFA sign-ins with a country
- successful medium/high-risk sign-ins with a country

`correlation.group_by: [user]` keeps the sequence within one identity. Step 1 establishes `country`. Step 2 declares `match_changed_fields: [country]`, so the second sign-in must come from a different country. `correlation.window_seconds: 1800` requires the second sign-in at or after the first and within 30 minutes.

The detection does not require the second sign-in to be interactive. Token replay and other non-interactive flows can satisfy the second step when risk is elevated.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Detect a risky sign-in from a new country after an interactive MFA sign-in |

## Test corpus

The package contains 14 synthetic events across eight scenarios:

- 2 positive scenarios with a risky sign-in from a different country.
- 3 negative scenarios: same country; low-risk new country; failed new-country sign-in.
- 3 benign scenarios: interactive only; risky only; normal refresh in the same country.

Metrics are scenario-level: 2 positive scenarios, 3 negative scenarios, and 3 benign scenarios.

## Known gaps

- VPN, corporate proxy, and mobile-network egress can change the apparent country.
- Nearby-country travel within the window can produce a false positive.
- The detection depends on location enrichment being present and accurate.
- It does not calculate travel distance or speed.
- The detection does not inspect device or token-protection signals.
- The Sigma representation covers only the interactive MFA component.

## Next tuning step

Add travel distance and network-velocity calculations, then correlate the second sign-in with mail, file, or cloud actions.
