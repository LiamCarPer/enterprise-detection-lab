# Runbook — Successful Risky Sign-In With Single-Factor Authentication

## Alert meaning

A user completed an interactive Entra ID sign-in while Entra risk was medium or high, and the session used single-factor authentication. This can be a compromised password, a conditional-access gap, or a legitimate but risky travel or device event.

## Triage

1. Confirm the sign-in result, application, IP address, device, and authentication requirement.
2. Identify the Entra risk detections that raised the score, such as unfamiliar sign-in properties, anonymous IP, or leaked credentials.
3. Check whether the user completed MFA in a related sign-in or recovered the account after this event.
4. Review the user's recent sign-in history for new locations, devices, or applications.
5. Pivot to Entra audit logs for consent grants, service principal changes, or credential changes.
6. Pivot to CloudTrail and endpoint telemetry from the same user or IP if those sources are available.

## Evidence

- `event_id`, `event_time`, `user`, `src_ip`, `app`, `action`, and `result`
- `auth_requirement`, `risk_level`, `is_interactive`, and device fields
- Related sign-in and audit events for the same user or IP
- Risk detection names and timestamps
- Conditional Access policy evaluation and any exclusions

## Escalation

Escalate when any of the following is true:

- The user did not perform the sign-in.
- The sign-in is followed by consent, credential, role, or mailbox changes.
- The source IP is associated with known malicious infrastructure.
- Multiple users show similar risky sign-ins from the same IP or device.
- The account has privileged directory or cloud roles.

## Containment

- Revoke the user's sessions and refresh tokens.
- Reset the password and require MFA re-registration if compromise is suspected.
- Review and remove suspicious application consents or service principal ownership grants.
- Block the source IP only after checking shared infrastructure and business impact.
- Preserve sign-in, audit, and cloud evidence before making changes.

## False positives

- Legitimate travel with an elevated risk score and successful MFA.
- New personal devices enrolled by the user.
- Stale risk detections or incomplete identity data.
- Break-glass accounts or service identities intentionally excluded from MFA.

## Closure

Document the sign-in outcome, the risk detections reviewed, the related identity and cloud activity, the containment actions, and any policy or detection tuning. If the event was benign, record which control or user action resolved it.

## References

- Microsoft Entra ID sign-in logs
- Microsoft Entra ID Protection risk detections
- MITRE ATT&CK T1078 — Valid Accounts
