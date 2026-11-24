# Runbook — GitHub Organization Owner Added

## Alert meaning

A GitHub account joined an organization as an owner or was promoted from member to owner. Owners can control repositories, secrets, Actions, apps, membership, and audit settings.

## Triage

1. Identify the actor, affected user, organization, source IP, user agent, and time.
2. Confirm whether the owner change matches an approved appointment or emergency access request.
3. Check the actor's recent activity for token creation, SSH key changes, app installation, repository visibility changes, and secret access.
4. Review the affected user's recent commits, workflow changes, and membership changes.
5. Check for owner changes across other organizations and enterprises.
6. Review audit-log streaming and retention settings for tampering.
7. Look for a second owner addition or a reverted role change that suggests temporary privilege use.

## Evidence

- `event_id`, `event_time`, `user`, `src_ip`, `organization`, `target_user`, and `role`
- Raw `old_permission` and `permission` values
- Actor token type and user agent
- Related owner, app, token, and repository events
- Change ticket or emergency-access record
- Repository and secret inventory changes after the promotion

## Escalation

Escalate when:

- The promotion is not tied to an approved request.
- The actor is an automation token, contractor, or unfamiliar account.
- The new owner is a newly created or dormant account.
- The change is followed by secret access, workflow edits, repository visibility changes, or audit setting changes.
- Multiple organizations have similar owner changes.

## Containment

- Demote or remove the unauthorized owner after preserving evidence.
- Revoke the actor's tokens and sessions.
- Rotate organization and repository secrets if exposure is possible.
- Review and revert unauthorized repository, workflow, app, and audit-setting changes.
- Preserve audit-log evidence before removing accounts or tokens.

## False positives

- An approved appointment of a new owner.
- Break-glass or emergency owner access during an incident.
- Administrative automation that manages ownership with a documented token.
- A planned ownership transfer during a reorganization.

## Closure

Record the business justification, approver, actor and token identity, related activity, containment, and whether the role was retained. Tune with a narrow automation identity or change-control integration, not a blanket owner exclusion.

## References

- GitHub organization audit log: org.add_member, org.update_member
- MITRE ATT&CK T1098 — Account Manipulation
