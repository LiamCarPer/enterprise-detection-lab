# Runbook — Risky Sign-In Followed by OAuth Consent Grant

## Alert meaning

A user completed a successful interactive sign-in with medium or high risk and single-factor authentication, then granted a user consent to an application outside the approved inventory with `offline_access` within 30 minutes. The sequence can indicate consent phishing and durable application access.

## Triage

1. Confirm both events share the same user and fall inside the 30-minute window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Review the application name, owner organization, publisher, publisher reputation, redirect URI, and requested scopes.
4. Confirm why the application is absent from the approved inventory and whether the user intended to connect it.
5. Check for application mail, file, or directory access after the consent.
6. Review other users who consented to the same application.
7. Pivot to Microsoft 365 audit, Exchange message trace, and CloudTrail for the same application and time window.

## Evidence

- Risky sign-in event and risk detection names
- Consent event, target service principal, `consent_type`, `scopes`, and `offline_access`
- Application owner organization, publisher details, and publisher reputation
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Application access after consent
- Approved application inventory or change ticket

## Escalation

Escalate when:

- The user did not intend to connect the application.
- The application owner is external or the publisher is unverified.
- The consent includes mail, file, or directory scopes with offline access.
- The application accesses sensitive mailboxes or files after consent.
- Other users consented to the same application.

## Containment

- Revoke the user's consent and refresh tokens.
- Disable or remove the application service principal after preserving evidence.
- Revoke application credentials and review application permissions.
- Review mailbox and file access for the application.
- Reset the user's credentials if the sign-in itself is suspicious.
- Add the application to a tenant deny or approval workflow if appropriate.

## False positives

- Unreviewed but legitimate application onboarding that uses user consent with offline access.
- A legitimate personal-productivity application that the user intended to connect.
- A risk false positive followed by an approved consent workflow.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, event lateness, and clock skew require separate handling. Grouping by `user` assumes the consent was initiated by the same user as the sign-in; application-only audit events may require a different group key.

## References

- Microsoft Entra ID sign-in and audit logs
- Microsoft Entra application consent and permission grants
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1528 — Steal Application Access Token
