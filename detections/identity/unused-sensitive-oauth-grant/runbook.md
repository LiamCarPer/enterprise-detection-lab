# Runbook — Unused Sensitive OAuth Grant

## Alert meaning

A scheduled review found an unapproved application with a sensitive OAuth grant and offline access that produced no observed Microsoft 365 mail, file, or Teams activity in the following 30 days. The grant may be abandoned, over-scoped, or dormant persistence.

## Triage

1. Confirm the grant date, application identity, consent type, and requested scopes.
2. Confirm the application is still present and has not been removed or disabled.
3. Check whether the application has a documented owner, business justification, and approval record.
4. Review application activity across mail, SharePoint, OneDrive, and Teams over a wider window.
5. Check for activity through APIs, workloads, or regions that are not represented in the audited telemetry.
6. Review the application's credentials, redirect URIs, and publisher reputation.
7. Ask the application owner whether the grant is still required.

## Evidence

- Grant event, operation name, target application, `app_id`, and `consent_type`
- `scopes`, `scope_categories`, `sensitive_scope`, and `offline_access`
- `approved_app`, `publisher_reputation`, `publisher_verified`, `redirect_uri_trusted`, and `redirect_uri`
- Absence of application activity across the review window and workload coverage
- Application owner, approval record, and business justification
- Last known application activity from a wider search

## Review outcome

- **Retain:** owner confirms the integration is required and the scopes are justified.
- **Reduce:** remove unused scopes, redirect URIs, or credentials.
- **Revoke:** remove the grant and service principal when no owner or justification exists.
- **Escalate:** treat as suspected persistence when the grant is unexplained, the publisher is untrusted, or the grant was created after a risky sign-in.

## Containment

- Revoke the grant and refresh tokens when the application is not required.
- Disable or remove the application service principal after preserving evidence.
- Remove unused credentials and redirect URIs.
- Add the application to a tenant deny or approval workflow if it is unknown.
- Record the review decision, owner, and expiry in the access-review system.

## False positives

- A seasonal or intermittent application whose activity falls outside the review window.
- An application that uses an API or workload not represented in the audited telemetry.
- An approved application with a stale inventory entry or redirect allowlist.
- A newly created grant that has not had time to produce activity.

## Correlation limits

This is a retrospective review detection. It reports absence of observed activity, not absence of risk. Telemetry coverage, event latency, and workload licensing determine whether the application's activity is visible.

## References

- Microsoft Entra ID audit logs
- Microsoft 365 unified audit log
- Microsoft Entra application consent and permission grants
- MITRE ATT&CK T1528 — Steal Application Access Token
