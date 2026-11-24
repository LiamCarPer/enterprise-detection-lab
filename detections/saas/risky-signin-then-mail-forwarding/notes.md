# Detection Notes — DET-SAA-003

## Hypothesis

A risky single-factor sign-in followed by a mailbox forwarding rule within an hour is more suspicious than either event alone. The sequence combines initial access risk with a durable email-collection mechanism that survives a password reset.

## Query and correlation design

The native query returns candidate events from two sources:

- successful interactive sign-ins with medium or high risk and single-factor authentication
- successful Microsoft 365 inbox rule creation or updates with a forwarding recipient

`correlation.group_by: [user]` requires both steps to share the user. `correlation.window_seconds: 3600` requires the mailbox step to occur at or after the sign-in and within 60 minutes. The window is wider than the identity-to-application correlation because Microsoft 365 audit records can arrive late.

The Sigma rule represents the sign-in component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Correlate sign-in risk with mailbox collection |

## Test corpus

The package contains 12 synthetic events across six scenarios:

- 2 positive scenarios with an in-window forwarding rule by the same user.
- 2 negative scenarios: rule outside the window; rule by a different user.
- 2 benign scenarios: approved forwarding after a normal sign-in; risky sign-in followed by a non-forwarding mailbox rule.

Metrics are scenario-level: 2 positive scenarios, 2 negative scenarios, and 2 benign scenarios.

## Known gaps

- Grouping by `user` does not distinguish a mailbox owner from a delegate acting on the mailbox.
- The query does not require the sign-in and mailbox events to come from the same IP or device.
- The correlation does not model Microsoft 365 audit latency beyond the one-hour window.
- The query does not compare the forwarding recipient with the organization's accepted domains.
- A compromised administrator can create an approved-looking rule after a legitimate sign-in.
- The Sigma representation covers only the sign-in component.

## Next tuning step

Add recipient-domain context so the alert can prioritize external forwarding, and correlate the sequence with mailbox-level forwarding, delegate changes, and subsequent mail access. Consider a shorter window for interactive sessions and a longer window for delegated administration.
