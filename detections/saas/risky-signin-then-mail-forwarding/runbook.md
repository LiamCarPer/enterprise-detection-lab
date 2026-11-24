# Runbook — Risky Sign-In Followed by Mail Forwarding Rule

## Alert meaning

A user signed in successfully with medium or high risk and single-factor authentication, then created or updated a Microsoft 365 inbox rule with a forwarding recipient within 60 minutes. The sequence can indicate credential compromise followed by email collection.

## Triage

1. Confirm both events share the same user and occur within the window.
2. Review the sign-in risk detections, source IP, device, and authentication method.
3. Review the mailbox rule name, forwarding recipient, conditions, and creation method.
4. Determine whether the forwarding recipient is internal or external.
5. Check for other mailbox changes: additional rules, mailbox-level forwarding, delegate changes, and mailbox permission changes.
6. Review the user's recent mail access and any messages sent or deleted.
7. Pivot to endpoint, cloud, and network telemetry for the same user and time window.

## Evidence

- Risky sign-in event and risk detection names
- Mailbox rule event, rule name, and forwarding recipient
- `user`, `src_ip`, `event_time`, and event IDs for both steps
- Raw M365 `Parameters` for all rule conditions
- Mailbox ownership and delegation records
- Related mail access and outbound activity
- Change ticket or approved forwarding request

## Escalation

Escalate when:

- The user did not perform the sign-in.
- The forwarding recipient is external and not approved.
- The rule forwards all mail or targets finance, executive, or credential-related messages.
- The rule is followed by mail access, deletion, or additional forwarding changes.
- Multiple mailboxes show the same pattern.

## Containment

- Disable or remove the unauthorized rule after preserving the audit record.
- Remove mailbox-level forwarding if present.
- Revoke the user's sessions and require a credential reset.
- Review sent and received mail for data exposure.
- Preserve identity, mailbox, and endpoint evidence before cleanup.

## False positives

- A legitimate user creates a forwarding rule after traveling or using a new device.
- A risk false positive is followed by an approved mailbox workflow.
- A delegate creates a forwarding rule for a mailbox owner who recently signed in.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, Microsoft 365 audit latency, and clock skew require separate handling. Grouping by `user` assumes the same identity appears in both events; delegated mailbox changes may require a mailbox or owner key.

## References

- Microsoft Entra ID sign-in logs
- Microsoft Purview audit log: New-InboxRule, Set-InboxRule
- MITRE ATT&CK T1078 — Valid Accounts
- MITRE ATT&CK T1114.003 — Email Collection: Email Forwarding Rule
