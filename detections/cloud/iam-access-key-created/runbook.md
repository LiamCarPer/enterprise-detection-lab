# Runbook — IAM Access Key Created

## Alert meaning

An AWS IAM user or root identity created an access key. Access keys provide durable programmatic credentials and are a common persistence and data-access mechanism after account compromise.

## Triage

1. Identify the initiating identity, target user, account, region, source IP, and user agent.
2. Confirm whether the key creation matches an approved onboarding or rotation workflow.
3. Check the target user's recent activity: console logins, role assumptions, key changes, and IAM policy changes.
4. Review CloudTrail for use of the new key, especially from new IPs or regions.
5. Check for other persistence actions: CreateUser, CreateLoginProfile, AttachUserPolicy, CreateRole, and UpdateAssumeRolePolicy.
6. Review the source IP and user agent against known automation and administrator infrastructure.

## Evidence

- `event_id`, `event_time`, `user`, `identity_type`, `src_ip`, `account`, and `region`
- Target user name from the request body
- New access key ID when available
- Related CloudTrail events for the same identity and source IP
- Change ticket or automation reference
- Key age and usage after creation

## Escalation

Escalate when:

- The key creation is not tied to an approved workflow.
- The initiating identity is a root user, contractor, or unexpected automation account.
- The new key is used from a new IP, region, or user agent.
- The event is followed by policy changes, role changes, or data access.
- Multiple keys are created across accounts.

## Containment

- Deactivate the new access key after preserving evidence.
- Rotate or delete unauthorized keys.
- Revoke the initiating identity's sessions and rotate its credentials if compromised.
- Review and revert unauthorized IAM policy, role, and trust changes.
- Preserve CloudTrail evidence before deleting resources.

## False positives

- Approved onboarding automation for a documented service account.
- Credential rotation by a managed pipeline.
- Break-glass or recovery activity with an approved change record.
- Migration tooling that creates temporary keys.

## Closure

Record the business justification, target user, key ID, related activity, containment, and any allow-list decision. Allow-list a specific automation identity and workflow, not all CreateAccessKey events.

## References

- AWS CloudTrail CreateAccessKey
- MITRE ATT&CK T1098.001 — Additional Cloud Credentials
- MITRE ATT&CK T1136.003 — Create Account: Cloud Account
