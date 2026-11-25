# Detection Notes — DET-SAA-006

## Hypothesis

A risky sign-in followed by self-delegation, mailbox access, and an external forwarding rule is a high-fidelity business email compromise chain. Each step is suspicious alone; the ordered sequence is much more specific.

## Query and correlation design

The native query returns candidates for four ordered steps:

- successful interactive sign-ins with medium or high risk and single-factor authentication
- self-granted mailbox or high-privilege folder permissions
- `MailItemsAccessed` events
- external inbox forwarding rules

`correlation.group_by: [user]` requires all steps to share the acting user. The permission, access, and forwarding steps declare `match_fields: [mailbox]`, so they must reference the same mailbox. `window_seconds: 3600` gives each successive step up to 60 minutes.

Microsoft 365 event classes distinguish permission grants (`mailbox_permission`), mailbox reads (`mail_access`), and forwarding rules (`mailbox`). The normalizer derives `mailbox` from `ObjectId` for inbox-rule and mail-access events.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Correlate the full mailbox takeover and forwarding chain |

## Test corpus

The package contains 23 synthetic events across six scenarios:

- 2 positive scenarios with all four steps in order and on the same mailbox.
- 2 negative scenarios: internal forwarding; forwarding outside the window.
- 2 benign scenarios: normal sign-in with delegation, access, and forwarding; risky sign-in with delegation and access but no forwarding.

Metrics are scenario-level: 2 positive scenarios, 2 negative scenarios, and 2 benign scenarios.

## Known gaps

- All steps must share the acting user; delegated administration by a separate admin account is out of scope.
- The query does not validate folder-level equality between access and forwarding.
- External forwarding is evaluated against the configured accepted domains.
- Mail flow outside Microsoft 365 audit coverage is not represented.
- The sequence may be split by audit latency beyond the one-hour window.
- The Sigma representation covers only the sign-in component.

## Next tuning step

Add delivery or mail-flow telemetry to confirm external mail left the tenant, and correlate the sequence with recipient replies or data-loss-prevention events. Tune with approved migration workflows rather than a blanket forwarding exclusion.
