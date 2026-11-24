# Runbook — Inbox Rule Created With Mail Forwarding

## Alert meaning

A Microsoft 365 mailbox rule was created or updated with `ForwardTo`, `RedirectTo`, or `ForwardAsAttachmentTo`. The rule can send future mail to another address without the mailbox owner signing in.

## Triage

1. Identify the actor, mailbox, rule name, forwarding recipient, source IP, and creation time.
2. Determine whether the forwarding recipient is internal or external.
3. Check whether the actor is the mailbox owner, a delegate, an administrator, or automation.
4. Review the actor's recent sign-ins for risky signals, new locations, failed MFA, or unusual user agents.
5. Inspect the rule conditions: a rule that forwards all mail or targets finance, invoices, approvals, or credentials is higher risk.
6. Look for related mailbox changes: additional rules, mailbox-level forwarding, delegate changes, and mailbox permission changes.
7. Review other mailboxes touched by the same actor or source IP.

## Evidence

- `event_id`, `event_time`, `user`, `src_ip`, `workload`, `object_id`, and `record_type`
- Rule name and forwarding recipient from `rule_name` and `forward_to`
- Raw `Parameters` for all rule conditions and actions
- Related sign-in and audit events for the actor
- Mailbox ownership and delegation records
- Change ticket or approved mail-flow request

## Escalation

Escalate when:

- The recipient is external and not tied to an approved workflow.
- The rule forwards all mail or targets finance, executive, or credential-related messages.
- The actor is not the mailbox owner or an approved delegate.
- The rule was created after a risky sign-in or from a new location.
- Multiple mailboxes have similar rules.

## Containment

- Disable or remove the unauthorized rule after preserving the audit record.
- Remove mailbox-level forwarding if present.
- Revoke the actor's sessions and reset credentials when compromise is likely.
- Review sent and received mail for data exposure.
- Preserve audit logs and rule parameters before cleanup.

## False positives

- A user creates a forwarding rule for a personal workflow.
- A delegate manages rules for an executive or shared mailbox.
- A migration or journaling process creates forwarding rules.
- An approved mail-flow change forwards messages to an internal team mailbox.

## Closure

Record the business justification, mailbox owner confirmation, recipient ownership, related sign-ins, containment, and whether the rule was removed. Tune with a narrow actor or mailbox allow-list, not a blanket forwarding exclusion.

## References

- Microsoft Purview audit log: New-InboxRule, Set-InboxRule
- MITRE ATT&CK T1114.003 — Email Collection: Email Forwarding Rule
