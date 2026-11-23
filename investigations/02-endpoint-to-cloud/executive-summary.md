# Executive Summary — INV-002

A synthetic endpoint chain began with encoded PowerShell on `LAB-EP-01`. Four minutes later, a failed network logon was recorded. Within 12 minutes, an IAM access key was created and CloudTrail logging was stopped.

The observed events are linked by host, user, source IP range, and timing. The lab does not contain a shared process or cloud session identifier, so the endpoint-to-cloud link remains an inference.

## Impact

The synthetic chain could provide durable cloud credentials while reducing audit visibility. No real hosts, users, accounts, or data are involved.

## Recommendation

Isolate the host, deactivate the new key, restore CloudTrail logging, and add correlation between endpoint execution and cloud credential creation.
