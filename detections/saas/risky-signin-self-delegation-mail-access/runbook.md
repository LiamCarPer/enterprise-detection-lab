# Runbook — Risky Sign-In, Self-Delegation, and Mail Access

## Alert meaning

A user signed in with medium or high risk and single-factor authentication, granted themselves mailbox or folder access, and then accessed a mailbox within 60 minutes per step. The sequence can indicate account takeover and email collection.

## Triage

1. Confirm the three events share the same user, are ordered correctly, and fall within the window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Identify the target mailbox, folder, access rights, and delegation time.
4. Determine whether the user legitimately needed access to the target mailbox.
5. Review mail access volume, folders touched, and messages read or exported.
6. Check for forwarding rules, delegate changes, and additional permissions.
7. Pivot to endpoint, cloud, and network telemetry for the same user and window.

## Evidence

- Risky sign-in event and risk detection names
- Mailbox or folder permission event, target, and access rights
- Mail access event, mailbox, folder, and access type
- `user`, `src_ip`, `event_time`, and event IDs for all three steps
- Raw M365 `Parameters` and `ObjectId`
- Mailbox ownership and delegation history
- Related forwarding, permission, and mail-flow changes

## Escalation

Escalate when:

- The user did not perform the sign-in.
- The self-delegation is not approved.
- The target mailbox belongs to an executive, finance, or other sensitive function.
- Mail access includes sensitive folders or high message volume.
- The sequence is followed by forwarding rules, external mail, or additional permissions.

## Containment

- Remove the unauthorized permission after preserving audit records.
- Revoke the user's sessions and require a credential reset.
- Review and remove related forwarding rules or delegate changes.
- Review mail access and data exposure for the target mailbox.
- Preserve identity, mailbox, and endpoint evidence before cleanup.

## False positives

- A legitimate user grants themselves access to a shared mailbox after traveling.
- A risk false positive followed by approved mailbox access.
- Break-glass administration during an incident.
- An approved migration or support workflow.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, audit latency, and clock skew require separate handling. Grouping by `user` assumes the same identity appears in all steps; delegated administration by a separate admin account is out of scope.

## References

- Microsoft Entra ID sign-in logs
- Microsoft Purview audit log: Add-MailboxPermission, Add-MailboxFolderPermission, MailItemsAccessed
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1098 — Account Manipulation
- MITRE ATT&CK T1114.002 — Remote Email Collection
