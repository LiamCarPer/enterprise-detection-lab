# Detection Notes — DET-IDN-003

## Hypothesis

A risky single-factor sign-in followed by a service principal ownership change within 30 minutes is more suspicious than either event alone. The sequence combines initial access risk with application persistence.

## Query and correlation design

- The native query returns candidate events from two identity sources:
  - successful interactive sign-ins with medium/high risk and single-factor authentication
  - successful owner additions to service principals
- `correlation.group_by: [user]` requires both steps to share the initiating user.
- `correlation.window_seconds: 1800` requires the audit step to occur at or after the sign-in and within 30 minutes.
- The runner evaluates ordered scenarios over the query results.

The Sigma rule represents the sign-in component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner; it is not represented as a native Sigma correlation rule yet.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Compose risky sign-in and ownership persistence |

## Test corpus

The package contains 12 synthetic events across six scenarios:

- 2 positive scenarios with an in-window owner addition by the same user.
- 2 negative scenarios: owner addition outside the window; owner addition by a different user.
- 2 benign scenarios: normal sign-ins without an audit step; routine service principal changes without a sign-in step.

Metrics are scenario-level: 2 positive scenarios, 2 negative scenarios, and 2 benign scenarios. The committed metrics state this explicitly.

## Known gaps

- Grouping by `user` may miss application-only audit events with no user principal.
- The correlation does not consider event lateness, clock skew, or duplicate delivery.
- The query does not require the sign-in and audit events to come from the same IP or device.
- The Sigma representation covers only the sign-in component.
- A compromised administrator can satisfy both steps with legitimate access.

## Next tuning step

Add optional grouping by application and source IP, then correlate with CloudTrail access key creation or CloudTrail logging changes for the same user and window.
