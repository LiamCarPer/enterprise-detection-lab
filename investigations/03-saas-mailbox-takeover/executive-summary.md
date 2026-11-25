# Executive Summary — INV-003

A synthetic SaaS chain began with a medium-risk single-factor sign-in. Within 45 minutes, the analyst granted themselves FullAccess to an executive mailbox, accessed the inbox, created an external forwarding rule, and updated that rule to a second external recipient.

The observed events are linked by the analyst identity, source IP, target mailbox, and timing. The investigation does not observe outbound message delivery or prove a single actor because message-trace and data-loss-prevention telemetry are not in scope.

## Impact

The synthetic chain could provide persistent access to executive email and a durable external collection path. No real users, mailboxes, or data are involved.

## Recommendation

Revoke the analyst sessions, remove the delegation and forwarding rule, review the executive mailbox for data exposure, and add message-trace telemetry to confirm outbound delivery.
