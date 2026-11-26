# Detection Notes — DET-IDN-004

## Hypothesis

A risky single-factor sign-in followed by user consent to an application with offline access can indicate consent phishing. The consent gives the application durable access to mail or files without another sign-in prompt.

## Query and correlation design

The native query returns candidate events from two identity sources:

- successful interactive sign-ins with medium or high risk and single-factor authentication
- successful user consent grants with `offline_access` for a service principal

`correlation.group_by: [user]` requires both steps to share the initiating user. Step 1 requires `result: success`, `risk_level: medium` or `high`, `auth_requirement: singleFactorAuthentication`, and `is_interactive: true`. Step 2 requires `action: Consent to application`, `result: success`, `consent_type: user`, `offline_access: true`, and `resource.type: ServicePrincipal`. `correlation.window_seconds: 1800` requires the consent at or after the sign-in and within 30 minutes.

The Sigma rule represents the consent component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Compose risky sign-in and user consent with offline access |

## Test corpus

The package contains 14 synthetic events across eight scenarios:

- 2 positive scenarios with an in-window user consent that includes `offline_access`.
- 3 negative scenarios: admin consent; consent after a low-risk sign-in; consent without `offline_access`.
- 3 benign scenarios: normal sign-in plus approved admin consent; risky sign-in without consent; consent without a sign-in.

Metrics are scenario-level: 2 positive scenarios, 3 negative scenarios, and 3 benign scenarios.

## Known gaps

- The correlation relies on the user consent record, not on downstream application access.
- A user consent to a legitimate application can match if the sign-in risk was elevated.
- Admin consent is excluded; it is a separate administrative path with different approval expectations.
- The detection does not verify the application publisher, redirect URI, or tenant trust.
- Grouping by `user` may miss application-only audit events.
- The Sigma representation covers only the consent component.

## Next tuning step

Add publisher and redirect-URI trust checks, then correlate consent with application mail or file access for the same application.
