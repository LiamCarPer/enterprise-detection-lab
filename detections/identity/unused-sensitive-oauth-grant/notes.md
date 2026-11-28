# Detection Notes — DET-IDN-012

## Hypothesis

A sensitive OAuth grant that is never followed by application activity may be abandoned, over-scoped, or created for persistence and left dormant. A scheduled review can identify grants that should be revoked or re-approved.

## Query and correlation design

The native query returns two candidate groups:

- successful Entra audit consent or OAuth permission grants to unapproved applications with `sensitive_scope: true` and `offline_access: true`
- successful Microsoft 365 application activity with `app_access: true`

`correlation.group_by: [app_identity]` groups grants and activity by application display identity. The required step is the sensitive grant. Three exclusion steps cover mailbox, SharePoint, and Teams application activity. An exclusion event suppresses the finding when it occurs after the grant and within 30 days. If no application activity is observed in that window, the grant is reported as unused.

This is a retrospective review detection. It is intended for a scheduled job over a closed 30-day window, not for inline alerting on the grant event. The detection runner replays the full fixture set, which is why a grant-only positive scenario can be evaluated.

The Sigma rule represents the sensitive-grant component. The absence-based review window and application-activity exclusions are defined in `meta.yaml` and the native query.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Identify sensitive grants with no application activity in 30 days |

## Test corpus

The package contains 20 synthetic events across twelve scenarios:

- 3 positive scenarios: a sensitive grant with no activity; a sensitive grant with user-only mail access; a sensitive grant with application activity after the 30-day window.
- 3 negative scenarios: a sensitive grant followed by application mail, file, or Teams activity within the window.
- 6 benign scenarios: approved sensitive grants, approved activity, non-sensitive grants, and non-sensitive activity.

Metrics are scenario-level: 3 positive scenarios, 3 negative scenarios, and 6 benign scenarios.

## Known gaps

- Application identity is derived from a display name in the modeled data; display names are not immutable and can collide.
- Activity outside the audited workloads, or activity that is not logged, looks like an unused grant.
- A seasonal application can be flagged during its inactive period.
- The 30-day window is a policy choice and should be tuned to the tenant's review cadence.
- The detection does not evaluate whether the grant was approved through a separate workflow that is not reflected in the application inventory.
- The Sigma representation covers only the grant component.

## Next tuning step

Add grant age and last-activity fields from an identity inventory, expose the review window as configuration, and produce a periodic access-review report with owner and business-justification context.
