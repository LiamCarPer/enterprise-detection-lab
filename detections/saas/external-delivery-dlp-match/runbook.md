# Runbook — External Delivery Confirmed by DLP Alert

## Alert meaning

A successful Exchange Online message-trace delivery sent a message to an external recipient, and an active high-severity Microsoft Purview DLP alert matched the same message within 30 minutes. The sequence confirms that a policy matched sensitive content on a message that left the tenant.

## Triage

1. Confirm the delivery and alert share the same `MessageId` and occur within the window.
2. Review the DLP policy name, severity, action, and the alert's `User` and `Recipient`.
3. Review the message-trace `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, and `RelatedRecipientAddress`.
4. Open the DLP alert and inspect the matched sensitive information types and the item that matched.
5. Check whether the recipient is an approved partner, archive, or personal address.
6. Review the sender's recent sign-ins, mailbox rules, delegation, and mail access.
7. Pivot to endpoint and network telemetry for the sender and the message time.

## Evidence

- Exchange message-trace detail record for the external delivery
- Purview DLP alert, including policy name, severity, action, matched condition, and status
- Shared `message_id`, `event_time`, `user`, `recipient`, and event IDs for both steps
- The rule or client that submitted the message, when available
- Approval records for external sharing
- Related mailbox and identity activity

## Escalation

Escalate when:

- The external recipient is not approved.
- The DLP policy covers regulated, financial, customer, or credential data.
- The sender shows concurrent mailbox-rule, delegation, or access changes.
- The same recipient appears across multiple DLP alerts.
- The alert is part of a larger sequence with forwarding or mailbox takeover indicators.

## Containment

- Preserve the message-trace and DLP alert records before cleanup.
- Recall or remove the external message when the platform supports it.
- Revoke the sender's sessions and reset credentials if account compromise is suspected.
- Remove unauthorized forwarding or delegation after preserving evidence.
- Notify the data owner and follow the tenant's incident process for regulated data.

## False positives

- An approved external transfer of regulated data that a DLP policy is designed to monitor.
- A DLP policy that alerts on a broad content pattern and is tuned with an approved exception.
- A user sends data to an external recipient under a documented business process.

## Correlation limits

The runner evaluates the sequence over the fixture corpus. Production scheduling, DLP alert latency, message-id coverage, and clock skew require separate handling. The join requires both sources to expose the same message identifier.

## References

- Exchange Online message trace detail records
- Microsoft Purview data loss prevention alerts
- MITRE ATT&CK T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
