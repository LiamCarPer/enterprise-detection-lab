# Detection Notes — DET-IDN-011

## Hypothesis

A consent or OAuth permission grant to an unapproved application with Teams scopes and offline access can establish durable access to chats, channels, or message-sending capabilities. If the same application then reads or sends Teams messages, the sequence is stronger evidence of consent phishing or an illicit integration than the grant alone.

## Query and correlation design

The native query returns candidate events for two ordered steps:

- successful Entra audit consent or OAuth permission grants with `approved_app: false`, `sensitive_scope: true`, `scope_categories: teams`, and `offline_access: true`
- successful Microsoft 365 Teams activity with `app_access: true`

`correlation.group_by: [app_identity]` requires both steps to reference the same application display identity. `correlation.window_seconds: 3600` requires Teams activity at or after the grant and within 60 minutes.

The normalizer adds `scope_categories` for mail, file, directory, and Teams scopes, derives `sensitive_scope` from the categories, and adds `app_identity` plus `app_access` to Microsoft 365 audit events when the acting `UserId` is not a user principal name. Entra audit consent events use the target application display name as `app_identity`. This is a display-name key; a production integration should use an immutable application ID when the workload audit record provides one.

The detection accepts `ChatCreated`, `MessageRead`, `MessageSent`, and `TeamCreated` as Teams activity. The Sigma rule represents the consent component. The application-identity correlation and post-consent access check are defined in `meta.yaml` and the native query.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Correlate sensitive Teams grants with application Teams activity |

## Test corpus

The package contains 22 synthetic events across twelve scenarios:

- 3 positive scenarios: user consent, admin consent, and a tenant-wide grant with a Teams scope and offline access, each followed by Teams activity by the same application.
- 6 negative scenarios: no Teams scope; a different application performs Teams activity; activity before consent; user rather than application activity; activity outside the window; a file scope without a Teams scope.
- 3 benign scenarios: approved application consent and Teams activity; normal user Teams activity; approved application consent without activity.

Metrics are scenario-level: 3 positive scenarios, 6 negative scenarios, and 3 benign scenarios.

## Known gaps

- Application identity is derived from a display name in the modeled data; display names are not immutable and can collide.
- Teams audit coverage varies by workload and licensing; message read activity may not be recorded consistently.
- `scope_categories` covers a fixed set of Graph scopes and does not evaluate every delegated or application permission.
- An approved inventory entry with a stale redirect allowlist can suppress a real grant.
- The detection does not evaluate message content, channel sensitivity, or message volume.
- The Sigma representation covers only the consent component.

## Next tuning step

Use application IDs from workload audit records where available, add message volume and external-recipient context, and correlate Teams activity with mail and file activity from the same application.
