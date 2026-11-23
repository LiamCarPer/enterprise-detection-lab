# Detection Notes — DET-IDN-001

## Hypothesis

A successful interactive sign-in with medium or high Entra risk and single-factor authentication can indicate credential compromise or a conditional-access gap. The combination is more actionable than risk alone because the session did not require a second factor.

## Query design

- `source = entra-signin` keeps the query on the identity sign-in source.
- `result = success` excludes failed attempts, which are covered by separate authentication detections.
- `risk_level` is limited to `medium` and `high`; low and none are normal baseline.
- `auth_requirement = singleFactorAuthentication` identifies sessions that did not satisfy MFA.
- `is_interactive = true` excludes background and service authentication.

The native OpenSearch query uses the canonical fields produced by the identity normalizer. The Sigma rule uses the source-level Entra field names and is not executed by the current runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish the reference identity detection pattern |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive events spanning medium/high risk, multiple users, applications, and device types.
- 5 negative events that fail one condition each: MFA satisfied, failed result, non-interactive, low risk, or no risk.
- 5 benign events covering travel with MFA, routine access, background synchronization, a risk false positive, and partner access.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- No impossible-travel or new-country correlation.
- No allow-list for known break-glass or service accounts.
- Risk scoring depends on the Entra ID Protection tier and data quality.
- The Sigma rule is not converted or executed in this milestone.
- Conditional Access policy details are only partially represented in the canonical event.

## Next tuning step

Add a correlation with Entra audit activity and CloudTrail role or key activity for the same user within a time window. That would raise fidelity without narrowing the single-event detection.
