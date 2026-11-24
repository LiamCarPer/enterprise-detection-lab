# Detection Notes — DET-SAA-004

## Hypothesis

A risky single-factor sign-in followed by a FullAccess mailbox delegation within an hour is more suspicious than either event alone. The sequence combines initial access risk with a durable grant that lets another identity read and send mail from the target mailbox.

## Query and correlation design

The native query returns candidate events from two sources:

- successful interactive sign-ins with medium or high risk and single-factor authentication
- successful `Add-MailboxPermission` events with the `FullAccess` right

`correlation.group_by: [user]` requires both steps to share the user. `window_seconds: 3600` allows for Microsoft 365 audit latency while keeping the sequence tight.

The normalizer reads `Identity`, `User` or `Member`, and `AccessRights` from the audit parameters, producing canonical `mailbox`, `delegate`, and `access_rights` fields.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Correlate sign-in risk with mailbox delegation |

## Test corpus

The package contains 12 synthetic events across six scenarios:

- 2 positive scenarios with an in-window FullAccess grant by the same user.
- 2 negative scenarios: grant outside the window; grant by a different user.
- 2 benign scenarios: approved delegation after a normal sign-in; SendAs-only permission after a risky sign-in.

Metrics are scenario-level: 2 positive scenarios, 2 negative scenarios, and 2 benign scenarios.

## Known gaps

- Grouping by `user` assumes the actor appears in both events; delegated mailbox administration may use a different administrative identity.
- The query covers `Add-MailboxPermission` but not folder-level permissions or distribution-group membership.
- `access_rights` matching is case-sensitive and depends on the Exchange value shape.
- The detection does not require the sign-in and delegation to come from the same IP or device.
- An approved helpdesk workflow can produce the same sequence.
- The Sigma representation covers only the sign-in component.

## Next tuning step

Add folder-level permissions and mailbox delegate changes, correlate the sequence with subsequent mail access, and tune with a namespace or helpdesk-role allow-list rather than a blanket delegation exclusion.
