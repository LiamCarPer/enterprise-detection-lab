# Runbook — Sensitive OAuth Grant Followed by Application Teams Activity

## Alert meaning

An unapproved application received a consent or OAuth permission grant with a sensitive Teams scope and offline access, then performed Teams activity within 60 minutes. The sequence can indicate consent phishing, message collection, or application abuse.

## Triage

1. Confirm both events share the same application identity and fall inside the 60-minute window.
2. Review the grant operation, consent type, administrator or user, source IP, and requested scopes.
3. Confirm why the application is absent from the approved inventory and whether the publisher or redirect URI is trusted.
4. Review the Teams operation, chat or channel, and message scope.
5. Check for message sending, external participants, data collection, and additional Teams activity by the application.
6. Review other users and administrators who granted access to the application.
7. Pivot to Microsoft 365 audit and Entra audit for the same application and time window.

## Evidence

- Consent or grant event, operation name, target application, `app_id`, and `consent_type`
- `scopes`, `scope_categories`, `sensitive_scope`, and `offline_access`
- `approved_app`, `publisher_reputation`, `publisher_verified`, `redirect_uri_trusted`, and `redirect_uri`
- Application identity and Teams activity with operation, chat or channel, and message scope
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Approved application inventory or change ticket
- Other file, mail, or Teams activity by the application after the grant

## Escalation

Escalate when:

- The application is not approved or the publisher is untrusted.
- The grant includes mail, file, directory, or Teams scopes with offline access.
- The application sends messages to external participants or sensitive channels.
- The application accessed multiple chats, channels, or users.
- The Teams activity follows a risky user sign-in or a recently changed application redirect URI.

## Containment

- Revoke the application's consent and refresh tokens.
- Disable or remove the application service principal after preserving evidence.
- Revoke application credentials and review granted permissions.
- Review Teams messages and files accessed by the application.
- Remove external participants or sharing created by the application.
- Add the application to a tenant deny or approval workflow.
- Reset user or administrator credentials if the originating session is suspicious.

## False positives

- An unreviewed but legitimate Teams application that the user intended to connect.
- An approved application whose inventory entry is stale or whose redirect URI changed.
- A production integration whose consent was granted outside the normal approval workflow.

## Correlation limits

The correlation groups by application display identity. It does not prove that the same service principal performed both events when display names collide, and it does not observe token exchange. Teams audit coverage and event latency vary by workload and licensing.

## References

- Microsoft Entra ID audit logs
- Microsoft 365 unified audit log
- Microsoft Entra application consent and permission grants
- MITRE ATT&CK T1528 — Steal Application Access Token
- MITRE ATT&CK T1213 — Data from Information Repositories
