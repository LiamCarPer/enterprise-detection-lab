# Detection Notes — DET-SAA-005

## Hypothesis

A risky single-factor sign-in followed by a self-granted mailbox permission and then mailbox access indicates account takeover and email collection. The sequence combines initial access, privilege use, and the collection outcome.

## Query and correlation design

The native query returns candidates for three ordered steps:

- successful interactive sign-ins with medium or high risk and single-factor authentication
- successful mailbox or high-privilege folder permission grants where the delegate is the actor
- successful `MailItemsAccessed` events

`correlation.group_by: [user]` requires all steps to share the acting user. The permission and access steps declare `match_fields: [mailbox]`, so the sequence must target the same mailbox. Step `filters` require a successful risky single-factor sign-in, a successful self-delegation (`self_delegation: true`) with the expected `access_rights`, and a successful `MailItemsAccessed` event. `window_seconds: 3600` gives each successive step up to 60 minutes.

Microsoft 365 event classes distinguish the steps: permission grants use `mailbox_permission`, and mailbox reads use `mail_access`. The normalizer sets `self_delegation` by comparing the delegate with the actor and derives `mailbox` and `folder` from `MailItemsAccessed.ObjectId`.

The Sigma rule represents the sign-in component. The temporal correlation is defined in `meta.yaml`.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Combine sign-in risk, self-delegation, and mail access |

## Test corpus

The package contains 20 synthetic events across seven scenarios:

- 2 positive scenarios with all three steps in order and within the window.
- 3 negative scenarios: mail access outside the window; delegation to a different user; delegation and access to different mailboxes.
- 2 benign scenarios: normal sign-in plus self-delegation plus access; risky sign-in plus self-delegation without access.

Metrics are scenario-level: 2 positive scenarios, 3 negative scenarios, and 2 benign scenarios.

## Known gaps

- Grouping by `user` assumes the actor is the same identity for all three steps.
- The correlation matches the delegated and accessed mailbox, but does not verify folder-level equality.
- A mailbox can be accessed for legitimate reasons immediately after an approved delegation.
- The query uses `MailItemsAccessed`, which may be batched or delayed by the audit pipeline.
- The Sigma representation covers only the sign-in component.
- Mail access by another delegate is out of scope.

## Next tuning step

Add a shared target key so the delegation and mail access must reference the same mailbox, and correlate the sequence with forwarding-rule changes and external mail flow. Tune with approved delegation workflows rather than a blanket exclusion.
