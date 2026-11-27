# Runbook — Anomalous Token Sign-In Followed by Mail Access

## Alert meaning

Entra reported an anomalous-token risk on an unprotected, unbound, long-lived sign-in, and the same user accessed a mailbox within 30 minutes. The sequence can indicate token theft followed by mail collection.

## Triage

1. Confirm both events share the user and fall inside the 30-minute window.
2. Review the sign-in risk detections, token issuer, authentication protocol, token-protection status, token-binding status, and token age.
3. Review the mailbox access type, mailbox, client IP, and client application.
4. Check whether the sign-in or mail access is explained by a known client, device, or automation.
5. Review other mailbox, file, and directory access from the same session and IP.
6. Check for new inbox rules, delegation, or forwarding changes.
7. Review identity protection and conditional access policy coverage.

## Evidence

- Sign-in event with `risk_event_types`, `token_protection_status`, `token_binding_status`, `token_issued_at`, `long_lived_token`, `token_issuer_type`, and source IP
- Mail-access event with mailbox, access type, client IP, and event ID
- `user`, `event_time`, and session context for both steps
- Related mailbox rules, delegation, and forwarding changes
- Other activity from the same IP or token
- Conditional access and token-protection policy state

## Escalation

Escalate when:

- The user did not perform the sign-in or access the mailbox.
- The token was issued to an unexpected client or device.
- The mailbox access includes sensitive mailboxes or bulk collection.
- The session is followed by rule, delegation, or forwarding changes.
- The same token or IP appears across multiple users.

## Containment

- Revoke the user's sessions and refresh tokens.
- Require credential reset and MFA re-registration if compromise is suspected.
- Review and remove suspicious mailbox rules, delegation, or application grants.
- Block the source IP if policy allows.
- Review cloud credentials and access keys created from the session.

## False positives

- A legitimate token refresh that Entra flags as anomalous and is followed by normal mail access.
- A client that does not support token protection but is otherwise trusted.
- A risk false positive followed by routine mailbox activity.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, event lateness, and clock skew require separate handling. The detection assumes the same user principal is present on both the sign-in and the mail-access event.

## References

- Microsoft Entra ID sign-in logs and identity protection risk detections
- Microsoft 365 unified audit log `MailItemsAccessed`
- MITRE ATT&CK T1528 — Steal Application Access Token
- MITRE ATT&CK T1114.002 — Remote Email Collection
