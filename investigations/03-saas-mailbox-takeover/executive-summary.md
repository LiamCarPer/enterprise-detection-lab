# Executive Summary — INV-003

A synthetic SaaS chain began with a medium-risk single-factor sign-in. Within 45 minutes, the analyst granted themselves FullAccess to an executive mailbox, accessed the inbox, created an external forwarding rule, and updated that rule to a second external recipient. Message trace then observed a redirect from the executive mailbox and a delivery to an external recipient.

The observed events are linked by the analyst identity, source IP, target mailbox, and timing. Delivery is now observed rather than inferred; actor attribution remains inferred, and data-loss-prevention or content confirmation is still out of scope.

## Impact

The synthetic chain provided persistent access to executive email, a durable external collection path, and an observed external delivery. No real users, mailboxes, or data are involved.

## Recommendation

Revoke the analyst sessions, remove the delegation and forwarding rule, preserve the message-trace records, review the executive mailbox for data exposure, and add data-loss-prevention confirmation for future investigations.
