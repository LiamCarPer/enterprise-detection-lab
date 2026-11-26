# Runbook — Interactive Sign-In Followed by Risky Sign-In From a New Country

## Alert meaning

A user completed an interactive MFA sign-in from one country, then a medium/high-risk sign-in occurred from a different country within 30 minutes. The sequence can indicate impossible travel or token theft.

## Triage

1. Confirm both events share the user and fall inside the 30-minute window.
2. Review the first sign-in's MFA method, device, IP, and location.
3. Review the second sign-in's risk detections, device, client app, IP, and location.
4. Check whether VPN, corporate proxy, or mobile-network egress explains the country change.
5. Review mail, file, and cloud activity from the second location and session.
6. Check for other users or sessions from the second IP or country.
7. Review token-protection, conditional access, and device compliance status.

## Evidence

- First sign-in event with MFA context and location
- Second sign-in event with risk level, location, and source IP
- Device identifiers and client application
- `user`, `country`, `src_ip`, and event IDs for both steps
- Subsequent mail, file, and cloud activity from the second location
- Travel or network-change explanation

## Escalation

Escalate when:

- The user did not perform the second sign-in.
- The country change is not explained by travel, VPN, or a known proxy.
- The second sign-in is followed by mailbox, file, or cloud access.
- The same IP or country appears across multiple users.
- Token protection or device compliance signals are missing or failed.

## Containment

- Revoke the user's sessions and refresh tokens.
- Require credential reset and MFA re-registration if compromise is suspected.
- Review and remove suspicious mailbox rules, delegation, or application grants.
- Block the source IP or country if policy allows.
- Review cloud credentials and access keys created from the session.

## False positives

- A VPN or corporate proxy that changes the apparent country.
- A user who travels between nearby countries within the window.
- Risk false positives from stale location or IP enrichment.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, event lateness, and clock skew require separate handling. The detection assumes location enrichment is present on both sign-ins.

## References

- Microsoft Entra ID sign-in logs and location fields
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1550.001 — Use Alternate Authentication Material: Application Access Token
