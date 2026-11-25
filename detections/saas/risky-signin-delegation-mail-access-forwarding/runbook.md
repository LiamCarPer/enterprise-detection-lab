# Runbook — Risky Sign-In, Self-Delegation, Mail Access, and External Forwarding

## Alert meaning

A user signed in with medium or high risk and single-factor authentication, granted themselves mailbox access, accessed that mailbox, and created an external forwarding rule within 60 minutes per step. This is a high-fidelity business email compromise chain.

## Triage

1. Confirm all four events share the user and mailbox, are ordered correctly, and fall within the window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Confirm the self-delegation, its target mailbox, and the access rights.
4. Review the mailbox access volume, folders, and messages read.
5. Inspect the forwarding rule, recipient domain, and rule conditions.
6. Check for additional rules, delegate changes, and mailbox permission changes.
7. Pivot to endpoint, cloud, network, and mail-flow telemetry for the same user and mailbox.

## Evidence

- Risky sign-in event and risk detection names
- Mailbox permission event, target, and access rights
- Mail access event, mailbox, folder, and access type
- Forwarding rule event, rule name, and recipient
- `user`, `src_ip`, `event_time`, and event IDs for all four steps
- Raw M365 `Parameters` and `ObjectId`
- Mailbox ownership, delegation, and forwarding history
- External mail-flow or data-loss-prevention records

## Escalation

Escalate when:

- The user did not perform the sign-in.
- The self-delegation or forwarding rule is not approved.
- The target mailbox belongs to an executive, finance, or other sensitive function.
- The forwarding recipient is external and not an approved partner.
- The sequence is followed by message deletion, export, or additional rules.

## Containment

- Remove the forwarding rule and unauthorized permission after preserving audit records.
- Revoke the user's sessions and require a credential reset.
- Review and remove related delegate changes.
- Review mail access and external forwarding for data exposure.
- Preserve identity, mailbox, endpoint, and mail-flow evidence before cleanup.

## False positives

- An approved mailbox migration that includes delegation, access, and forwarding.
- A legitimate user configures forwarding after receiving delegated access.
- Break-glass administration during an incident.
- A documented mailbox ownership transfer.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, audit latency, and clock skew require separate handling. Grouping by `user` assumes the same identity appears in all steps; delegated administration by a separate admin account is out of scope.

## References

- Microsoft Entra ID sign-in logs
- Microsoft Purview audit log: Add-MailboxPermission, MailItemsAccessed, New-InboxRule
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1098 — Account Manipulation
- MITRE ATT&CK T1114.002 — Remote Email Collection
- MITRE ATT&CK T1114.003 — Email Forwarding Rule
