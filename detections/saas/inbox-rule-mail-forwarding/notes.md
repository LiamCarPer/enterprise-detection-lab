# Detection Notes — DET-SAA-001

## Hypothesis

An inbox rule that forwards or redirects mail lets an attacker receive messages without continuing to access the mailbox. Business email compromise actors commonly create these rules to collect invoices, approvals, and credentials while hiding the messages from the mailbox owner.

## Query design

- `source = m365-audit` restricts the query to the normalized Microsoft 365 audit source.
- `action` covers `New-InboxRule` and `Set-InboxRule`; both can add a forwarding action.
- `result = success` excludes failed attempts.
- `forward_to` is populated from `ForwardTo`, `RedirectTo`, or `ForwardAsAttachmentTo` in the audit record parameters.

The native query uses canonical fields. The Sigma rule uses source-level Unified Audit Log fields and is not executed by the runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish SaaS email-collection coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive forwarding-rule creations across new rules, rule updates, shared mailboxes, and attachment forwarding.
- 5 negative events covering message moves, read flags, failed creation, mailbox-level forwarding, and rule deletion.
- 5 benign Microsoft 365 events covering file access, mail synchronization, mailbox organization rules, and sign-in.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- The normalized event does not distinguish internal from external recipients.
- A rule can forward to more than one recipient; only the first forwarding parameter is indexed.
- `UpdateInboxRules` stores forwarding actions in a different parameter shape and is not normalized yet.
- Mailbox-level forwarding through `Set-Mailbox` is a separate behavior and is not covered.
- The query does not correlate rule creation with the actor's sign-in risk or source IP reputation.

## Next tuning step

Normalize the recipient domain and compare it with the organization's accepted domains so the alert can prioritize external forwarding. Add `UpdateInboxRules` support and correlate new rules with risky sign-ins and mailbox rule changes from the same actor.
