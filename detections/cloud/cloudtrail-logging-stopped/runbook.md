# Runbook — CloudTrail Logging Stopped

## Alert meaning

An AWS identity stopped logging on a CloudTrail trail. This can blind monitoring, disrupt evidence collection, and precede or accompany destructive or data-access activity.

## Triage

1. Identify the initiating identity, account, region, trail, source IP, and user agent.
2. Confirm whether the change matches an approved maintenance, migration, or test workflow.
3. Check the trail status and whether another trail or organization trail still records the account.
4. Review recent CloudTrail activity for the initiating identity, especially IAM changes and data access.
5. Check for related defense-evasion actions: DeleteTrail, UpdateTrail, PutEventSelectors, and GuardDuty changes.
6. Review authentication activity from the source IP and user agent.

## Evidence

- `event_id`, `event_time`, `user`, `identity_type`, `src_ip`, `account`, and `region`
- Trail name from the request body
- Current logging status and overlapping trails
- Related IAM, CloudTrail, and GuardDuty activity
- Change ticket or maintenance record
- Any data access or destructive actions after logging stopped

## Escalation

Escalate immediately when:

- The change is not approved.
- The initiating identity is root, a contractor, or an unexpected role.
- Multiple trails or accounts are affected.
- The event is followed by IAM changes, key creation, data access, or resource deletion.
- Another security control was disabled in the same window.

## Containment

- Re-enable logging on the affected trail.
- Preserve configuration and API evidence before changing the trail.
- Revoke the initiating identity's sessions and rotate credentials if compromised.
- Review and revert unauthorized trail, IAM, and security-control changes.
- Validate that organization trails and central logging still capture the account.

## False positives

- Approved trail maintenance or migration.
- Temporary test-trail changes in a non-production account.
- Recovery from a misconfigured trail with an approved change record.
- Automated remediation that recreates a trail under a new name.

## Closure

Record the change approval, trail status, overlap coverage, related API activity, containment, and any control improvement. Treat unexplained logging gaps as an evidence-integrity issue.

## References

- AWS CloudTrail StopLogging
- MITRE ATT&CK T1562.008 — Disable or Modify Cloud Logs
