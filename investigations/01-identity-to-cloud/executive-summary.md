# Executive Summary — INV-001

A synthetic identity chain began with a medium-risk single-factor sign-in. Within 35 minutes, a new service principal was created, an owner was added, an IAM access key was created, and CloudTrail logging was stopped.

The observed events are linked by the `analyst` identity, source IP ranges, and timing. The investigation does not prove a single actor because the lab does not contain an explicit role-assumption or token-exchange event.

## Impact

The synthetic chain could provide durable application ownership and programmatic cloud access while reducing audit visibility. No real users, accounts, or data are involved.

## Recommendation

Revoke the affected sessions and key, remove the unauthorized owner, restore CloudTrail logging, and add cross-domain correlation for identity persistence followed by cloud credential creation.
