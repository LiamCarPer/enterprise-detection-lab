# Runbook — Interactive Session Reused From a New IP

## Alert meaning

A user completed a successful interactive MFA sign-in, then the same session ID was used non-interactively from a different source IP with medium or high risk within 60 minutes. The sequence can indicate token or session replay.

## Triage

1. Confirm both events share the user and session ID, and verify the 60-minute window.
2. Review the interactive sign-in risk, MFA method, device, and source IP.
3. Review the non-interactive sign-in risk detections, client app, device, and source IP.
4. Check whether the IP change is explained by travel, VPN, mobile network, or a known proxy.
5. Review mail, file, and cloud activity from the second IP and session.
6. Check for other sessions or users from the second IP.
7. Review token protection, conditional access, and device compliance status.

## Evidence

- Interactive sign-in event and MFA context
- Non-interactive sign-in event, risk level, session ID, and source IP
- Device identifiers and client application
- `user`, `session_id`, `src_ip`, and event IDs for both steps
- Subsequent mail, file, and cloud activity from the second IP
- Travel or network-change explanation

## Escalation

Escalate when:

- The user did not perform the second sign-in.
- The second IP is not explained by travel, VPN, or a known network.
- The session is followed by mailbox, file, or cloud access.
- The same IP or session appears across multiple users.
- Token protection or device compliance signals are missing or failed.

## Containment

- Revoke the user's sessions and refresh tokens.
- Require credential reset and MFA re-registration if compromise is suspected.
- Review and remove suspicious mailbox rules, delegation, or application grants.
- Block the source IP if policy allows.
- Review cloud credentials and access keys created from the session.

## False positives

- A user changes networks during a long-lived session and the new session is independently risky.
- A mobile or VPN transition that changes the source IP.
- A risk false positive on a legitimate token refresh.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, event lateness, and clock skew require separate handling. The detection assumes the same session ID is preserved across the interactive and non-interactive events.

## References

- Microsoft Entra ID sign-in logs and session identifiers
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1550.001 — Use Alternate Authentication Material: Application Access Token
