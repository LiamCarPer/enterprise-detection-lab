# Runbook — Sensitive OAuth Grant Followed by Application File Access

## Alert meaning

An unapproved application received a consent or OAuth permission grant with a sensitive file scope and offline access, then accessed or downloaded files within 60 minutes. The sequence can indicate consent phishing followed by data collection from SharePoint or OneDrive.

## Triage

1. Confirm both events share the same application identity and fall inside the 60-minute window.
2. Review the grant operation, consent type, administrator or user, source IP, and requested scopes.
3. Confirm why the application is absent from the approved inventory and whether the publisher or redirect URI is trusted.
4. Review the site, library, file path, operation, and file count associated with the application activity.
5. Check for downloads, external sharing, permission changes, or additional site access by the same application.
6. Review other users and administrators who granted access to the application.
7. Pivot to Microsoft 365 audit and Entra audit for the same application and time window.

## Evidence

- Consent or grant event, operation name, target application, `app_id`, and `consent_type`
- `scopes`, `scope_categories`, `sensitive_scope`, and `offline_access`
- `approved_app`, `publisher_reputation`, `publisher_verified`, `redirect_uri_trusted`, and `redirect_uri`
- Application identity and file activity with site, library, file path, and operation
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Approved application inventory or change ticket
- Other file, mail, or Teams activity by the application after the grant

## Escalation

Escalate when:

- The application is not approved or the publisher is untrusted.
- The grant includes mail, file, or directory scopes with offline access.
- The application accessed finance, legal, HR, executive, or other sensitive sites.
- The application downloaded or shared files in bulk.
- The same application accessed multiple sites or users.
- External sharing or permission changes follow the access.

## Containment

- Revoke the application's consent and refresh tokens.
- Disable or remove the application service principal after preserving evidence.
- Revoke application credentials and review granted permissions.
- Review site and file access for the application.
- Remove external sharing or permission changes created by the application or user.
- Add the application to a tenant deny or approval workflow.
- Reset user or administrator credentials if the originating session is suspicious.

## False positives

- An unreviewed but legitimate file application that the user intended to connect.
- An approved application whose inventory entry is stale or whose redirect URI changed.
- A production integration whose consent was granted outside the normal approval workflow.

## Correlation limits

The correlation groups by application display identity. It does not prove that the same service principal performed both events when display names collide, and it does not observe token exchange. File activity batching and event latency can delay or split the sequence.

## References

- Microsoft Entra ID audit logs
- Microsoft 365 unified audit log
- Microsoft Entra application consent and permission grants
- MITRE ATT&CK T1528 — Steal Application Access Token
- MITRE ATT&CK T1213.002 — Data from Information Repositories: SharePoint
