# Runbook — Admin or Tenant OAuth Grant to Untrusted Application

## Alert meaning

An administrator completed a successful admin or tenant consent, or a tenant-wide OAuth permission grant, to an application with an unverified publisher or untrusted redirect URI. The grant can provide durable access for every user in the tenant.

## Triage

1. Confirm the operation, consent type, tenant-wide flag, and trust fields.
2. Review the application name, owner organization, publisher, redirect URI, and requested scopes.
3. Verify whether the application is approved and whether the redirect URI is expected.
4. Check whether the grant was part of a documented onboarding or emergency change.
5. Review other grants to the same application and other administrators involved.
6. Pivot to Microsoft 365 audit and Exchange message trace for application access after the grant.
7. Review the application's service principal, credentials, and role assignments.

## Evidence

- Consent or grant event, operation name, target application, and `consent_type`
- `tenant_wide`, `publisher_verified`, `redirect_uri_trusted`, and `redirect_uri`
- `scopes` and application owner organization
- Administrator identity, source IP, and event time
- Approved application inventory or change record
- Post-grant application access and permission grants

## Escalation

Escalate when:

- The application is not approved.
- The publisher is unverified or the redirect URI is untrusted.
- The grant is tenant-wide and includes mail, file, or directory scopes.
- The application accesses sensitive mailboxes or files after the grant.
- Multiple administrators or applications show the same pattern.

## Containment

- Revoke the tenant-wide grant and refresh tokens.
- Disable or remove the application service principal after preserving evidence.
- Revoke application credentials and review granted permissions.
- Review tenant-wide access to mail, files, and directory data.
- Add the application to a tenant deny or approval workflow.
- Reset administrator credentials if the grant is associated with a suspicious session.

## False positives

- Approved internal application onboarding before publisher verification completes.
- A tenant-wide grant to a verified application whose redirect URI is not yet in the trusted inventory.
- A break-glass or emergency application grant with an approved change record.

## Correlation limits

This is an event-level detection. It does not correlate the grant with a risky administrator sign-in, a specific user, or downstream application access.

## References

- Microsoft Entra ID audit logs
- Microsoft Entra application consent and permission grants
- MITRE ATT&CK T1528 — Steal Application Access Token
- MITRE ATT&CK T1098 — Account Manipulation
