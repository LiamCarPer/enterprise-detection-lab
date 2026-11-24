# Detection Notes — DET-SAA-001

## Hypothesis

An inbox rule that forwards or redirects mail lets an attacker receive messages without continuing to access the mailbox. Business email compromise actors commonly create these rules to collect invoices, approvals, and credentials while hiding the messages from the mailbox owner.

## Query design

- `source = m365-audit` restricts the query to the normalized Microsoft 365 audit source.
- `action` covers `New-InboxRule` and `Set-InboxRule`; both can add a forwarding action.
- `result = success` excludes failed attempts.
- `forward_to` is the first forwarding recipient from `Parameters` or `OperationProperties`.
- `forward_domains` contains every unique recipient domain in the rule.
- `forward_external` is true when any recipient domain is outside `EDL_ACCEPTED_MAIL_DOMAINS`.
- The tuned query uses `forward_external = true`, so accepted domains are configured once and are not hardcoded in the detection.

The native query uses canonical fields. The Sigma rule uses source-level Unified Audit Log fields and is not executed by the runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish SaaS email-collection coverage |
| 1.1.0 | Exclude the tenant accepted domain | Reduce internal forwarding noise after baseline tuning |
| 1.2.0 | Normalize all recipients and use configured accepted domains | Support multi-recipient and `UpdateInboxRules` events without hardcoding a domain |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive forwarding-rule creations across new rules, rule updates, shared mailboxes, and attachment forwarding.
- 5 negative events covering message moves, read flags, failed creation, mailbox-level forwarding, and rule deletion.
- 5 benign Microsoft 365 events covering file access, mail synchronization, mailbox organization rules, and sign-in.

A separate 20-event forwarding corpus is stored at `lab/datasets/synthetic/benign-baseline/m365-forwarding.json`. The initial query matched 8 internal forwarding events; the tuned query matches none. The before/after analysis is documented in [`reports/saas-forwarding-tuning.md`](../../../reports/saas-forwarding-tuning.md). The exclusion is recorded as `EXC-SAA-001-001`.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- Accepted domains come from `EDL_ACCEPTED_MAIL_DOMAINS` and must match the tenant's real domain inventory.
- An attacker can use an internal compromised account as the forwarding destination.
- `OperationProperties` field names can vary across Microsoft 365 workloads and client versions.
- Mailbox-level forwarding through `Set-Mailbox` is a separate behavior and is not covered.
- The event-level query does not correlate rule creation with the actor's sign-in risk or source IP reputation; `DET-SAA-003` covers that sequence.

## Next tuning step

Load accepted domains from a versioned tenant configuration rather than an environment variable, and validate the list during ingestion. Correlate new rules with risky sign-ins, delegated mailbox changes, and subsequent mail access.
