# Runbook — Denied Exception Followed by DLP-Confirmed External Delivery

## Alert meaning

A ServiceNow approval denied or revoked an external-sharing request, then the same mailbox delivered a message to the same recipient, and an active high-severity Purview DLP alert matched that message and content scope within 24 hours. The sequence indicates that a denied or revoked data-handling decision was bypassed. A later approved request for the same mailbox, recipient, and content scope suppresses the alert for up to seven days.

## Triage

1. Confirm the approval, delivery, and alert align on mailbox, recipient, message identity, and content scope.
2. Review the approval request number, requested-for mailbox, approver, decision time, and denial reason.
3. Review the message-trace `MessageId`, `SenderAddress`, `Subject`, `Status`, and `RelatedRecipientAddress`.
4. Open the DLP alert and inspect the matched sensitive information types, content scope, and policy action.
5. Check whether a later approval covers the same content, recipient, and seven-day window.
6. Review the sender's recent sign-ins, mailbox rules, delegation, and mail access.
7. Pivot to endpoint and network telemetry for the sender and message time.

## Evidence

- ServiceNow approval record with the request number, decision, approver, and timestamps
- Exchange message-trace detail record for the external delivery
- Purview DLP alert with policy, severity, action, and matched condition
- Shared `mailbox`, `delivery_recipient`, `message_id`, and `content_scope`
- Any later approval or exception that supersedes the denial
- Related identity, mailbox, and endpoint activity

## Escalation

Escalate when:

- No later approval covers the same content and recipient.
- The DLP policy covers regulated, financial, customer, or credential data.
- The sender shows concurrent mailbox-rule, delegation, or access changes.
- The same recipient appears across multiple denied, revoked, or alerted requests.
- The delivery is part of a larger sequence with forwarding or mailbox takeover indicators.

## Containment

- Preserve the approval, message-trace, and DLP records before cleanup.
- Recall or remove the external message when the platform supports it.
- Notify the data owner and follow the tenant's incident process for regulated data.
- Remove unauthorized forwarding or delegation after preserving evidence.
- Revoke sessions and reset credentials if account compromise is suspected.

## False positives

- An approval was denied or revoked for one dataset but a later request for different content was approved.
- A delivery used an approved exception recorded under a different request or message identifier.
- A DLP policy matched a message that the data owner later approved retrospectively.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, approval latency, DLP alert latency, message-id coverage, and clock skew require separate handling. The join assumes the approval record carries the delivered message identifier.

## References

- ServiceNow approval records
- Exchange Online message trace detail records
- Microsoft Purview data loss prevention alerts
- MITRE ATT&CK T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
