# Runbook — Forwarding Rule Followed by External Delivery

## Alert meaning

A successful Microsoft 365 inbox rule that forwards to an external domain was followed within 60 minutes by a successful Exchange Online message-trace delivery to an external recipient for the same mailbox. The sequence confirms that forwarded mail left the tenant.

## Triage

1. Confirm the rule and delivery resolve to the same mailbox and occur within the window.
2. Review the rule name, conditions, forwarding recipient, and creation or update method.
3. Compare the rule's forwarding recipient with the message-trace `RecipientAddress`.
4. Review the message-trace `MessageId`, `SenderAddress`, `Subject`, `Status`, and `RelatedRecipientAddress`.
5. Check for other mailbox changes: additional rules, mailbox-level forwarding, delegate changes, and permission grants.
6. Review the user's recent sign-ins, mail access, and source IPs.
7. Pivot to endpoint, cloud, and network telemetry for the same user and time window.

## Evidence

- Inbox rule event, rule name, forwarding recipient, and raw M365 `Parameters`
- Message-trace detail records for the same `MessageId`, `RecipientAddress`, and `RelatedRecipientAddress`
- `mailbox`, `event_time`, `external_recipient`, `forward_external`, and event IDs for both steps
- Mailbox ownership and delegation records
- Related mail access and outbound activity
- Change ticket or approved forwarding request

## Escalation

Escalate when:

- The user did not create the rule.
- The forwarding recipient is external and not approved.
- The rule forwards all mail or targets finance, executive, or credential-related messages.
- The rule is followed by mail access, deletion, or additional forwarding changes.
- Multiple mailboxes show the same pattern.

## Containment

- Disable or remove the unauthorized rule after preserving the audit and message-trace records.
- Remove mailbox-level forwarding if present.
- Revoke the user's sessions and require a credential reset.
- Review sent and received mail for data exposure.
- Preserve identity, mailbox, message-trace, and endpoint evidence before cleanup.

## False positives

- An approved external forwarding rule that the tenant intentionally uses to route mail.
- A journaling or migration process that forwards to an external archive.
- A user forwards mail to an external partner after an approved request.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, message-trace latency, retention differences, and clock skew require separate handling. Grouping by `mailbox` assumes message trace carries an internal related recipient for the original mailbox.

## References

- Microsoft 365 unified audit log: New-InboxRule, Set-InboxRule, UpdateInboxRules
- Exchange Online message trace detail records
- MITRE ATT&CK T1114.003 — Email Collection: Email Forwarding Rule
