# Runbook — Risky Sign-In Followed by Mailbox Delegation

## Alert meaning

A user completed a successful interactive sign-in with medium or high risk and single-factor authentication, then granted FullAccess to a mailbox or high-privilege access to a mailbox folder within 60 minutes. The sequence can indicate credential compromise followed by email collection.

## Triage

1. Confirm both events share the same user and occur within the window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Identify the target mailbox or folder, delegate identity, access rights, and whether the delegation was expected.
4. Review the mailbox for mail access, forwarding rules, delegate changes, and permission changes.
5. Check whether the actor has a helpdesk or mailbox-administration role.
6. Pivot to endpoint, cloud, and other SaaS telemetry for the same user and time window.
7. Review other mailboxes administered by the same actor.

## Evidence

- Risky sign-in event and risk detection names
- Mailbox or folder permission event, target mailbox, folder, delegate, and access rights
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Raw M365 `Parameters`
- Mailbox ownership and delegation history
- Related mail access, forwarding, and permission changes
- Change ticket or approved delegation request

## Escalation

Escalate when:

- The user did not perform the sign-in.
- The delegation is not tied to an approved request.
- The delegate is external, unexpected, or a newly created account.
- The target mailbox belongs to an executive, finance, or other sensitive function.
- The sequence is followed by mail access, forwarding changes, or additional delegation.

## Containment

- Remove the unauthorized mailbox permission after preserving the audit record.
- Revoke the actor's sessions and require a credential reset.
- Review and remove related forwarding rules or delegate changes.
- Review mail access and data exposure for the target mailbox.
- Preserve identity, mailbox, and endpoint evidence before cleanup.

## False positives

- An approved delegation request after legitimate travel or a new device.
- A risk false positive followed by helpdesk mailbox administration.
- Break-glass or emergency mailbox access during an incident.
- A documented mailbox ownership transfer.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, audit latency, and clock skew require separate handling. Grouping by `user` assumes the same identity appears in both events; delegated administration by a separate admin account needs a different correlation key.

## References

- Microsoft Entra ID sign-in logs
- Microsoft Purview audit log: Add-MailboxPermission
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1098 — Account Manipulation
- MITRE ATT&CK T1114.002 — Remote Email Collection
