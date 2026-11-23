# Runbook — Risky Sign-In Followed by Service Principal Ownership Change

## Alert meaning

A user completed a successful interactive sign-in with medium or high risk and single-factor authentication, then added an owner to a service principal within 30 minutes. The sequence can indicate credential compromise followed by application persistence.

## Triage

1. Confirm both events share the same user, and verify the 30-minute window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Review the service principal, new owner, application owner history, and any recent credential or consent changes.
4. Check whether the user or application owner approved the change through a documented workflow.
5. Pivot to CloudTrail and endpoint telemetry for the same user, IP, and time window.
6. Look for additional persistence: service principal creation, credentials, federated identity credentials, and role assignments.

## Evidence

- Risky sign-in event and risk detection names
- Service principal ownership event and target application
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Related audit, cloud, and endpoint activity
- Change ticket or approved automation reference
- Application credential and consent history

## Escalation

Escalate when:

- The user did not perform the sign-in.
- The ownership change is not approved.
- The application was created recently or has cloud access.
- The new owner is unexpected or external.
- The sequence is followed by access key creation, consent grants, or logging changes.

## Containment

- Revoke the user's sessions and require credential reset.
- Remove the unauthorized owner and review application credentials and permissions.
- Preserve both events and related identity, endpoint, and cloud evidence.
- Review and revert other application, consent, and role changes.
- Monitor the application and user for recurrence.

## False positives

- Approved ownership changes following legitimate travel or a new device.
- Risk false positives followed by approved administrative work.
- Break-glass or emergency identity administration.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, event lateness, and clock skew require separate handling. Grouping by `user` assumes the same initiating identity is used for both steps; application-only audit events may require a different group key.

## References

- Microsoft Entra ID sign-in and audit logs
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1098.002 — Additional Cloud Roles
