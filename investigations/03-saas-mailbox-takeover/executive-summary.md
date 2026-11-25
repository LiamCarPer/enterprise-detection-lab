# Executive Summary — INV-003

A synthetic SaaS chain began with a medium-risk single-factor sign-in. Within 45 minutes, the analyst granted themselves FullAccess to an executive mailbox, accessed the inbox, created an external forwarding rule, and updated that rule to a second external recipient. Message trace then observed a redirect from the executive mailbox and a delivery to an external recipient, and a high-severity DLP alert matched the delivered message.

The observed events are linked by the analyst identity, source IP, target mailbox, and timing. Delivery and a sensitive-content policy match are now observed rather than inferred; actor attribution and the recipient approval decision remain inferred.

## Impact

The synthetic chain provided persistent access to executive email, a durable external collection path, an observed external delivery, and a DLP alert on the delivered message. No real users, mailboxes, or data are involved.

## Recommendation

Revoke the analyst sessions, remove the delegation and forwarding rule, preserve the message-trace and DLP records, review the executive mailbox for data exposure, and confirm whether the external recipient was approved.
