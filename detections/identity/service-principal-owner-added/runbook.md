# Runbook — Owner Added to Service Principal

## Alert meaning

An identity added an owner to an Entra ID service principal. Application ownership can allow credential changes, permission changes, and persistence without creating a new credential immediately.

## Triage

1. Confirm the initiating user, target service principal, and operation time.
2. Check whether the change matches an approved onboarding, ownership transfer, or automation workflow.
3. Review the application's recent history: creation, credential changes, consent grants, and permission grants.
4. Confirm whether the initiating user is an expected application owner or identity administrator.
5. Review the new owner's recent sign-ins and audit activity.
6. Pivot to CloudTrail and endpoint telemetry if the application has cloud or workstation access.

## Evidence

- `event_id`, `event_time`, `user`, `action`, `result`, and `resource`
- Target service principal display name and type
- Initiating user and any application identity
- Related application creation, credential, consent, and role events
- Change ticket or approved automation reference

## Escalation

Escalate when:

- The change is not associated with an approved workflow.
- The service principal was created recently.
- The new owner is a non-administrator or unexpected external identity.
- The change is followed by credential, consent, role, or cloud activity.
- Multiple service principals receive the same unexpected owner.

## Containment

- Remove the unauthorized owner after preserving evidence.
- Review and rotate application credentials and certificates.
- Revoke the initiating user's sessions if compromise is suspected.
- Review the application's API permissions and consent grants.
- Disable the application if malicious control is confirmed.

## False positives

- Approved application onboarding by an identity administrator.
- Ownership transfer during an application migration.
- Managed automation that assigns owners from a documented workflow.
- Emergency changes recorded after the fact.

## Closure

Record the change ticket or approval, the application owner validation, related credential and consent activity, and any containment action. Add the service principal or initiating identity to an allow-list only if the workflow is documented and reviewed.

## References

- Microsoft Entra ID audit logs
- MITRE ATT&CK T1098.002 — Additional Cloud Roles
