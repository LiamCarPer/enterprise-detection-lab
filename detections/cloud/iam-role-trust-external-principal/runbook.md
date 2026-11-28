# Runbook — IAM Role Trust Policy Changed to External Principal

## Alert meaning

An IAM role was created or its trust policy was changed so that a wildcard principal or an AWS account outside the recipient account can assume it. This can provide cross-account access, persistence, or a path into the account.

## Triage

1. Identify the initiating identity, source IP, user agent, account, and region.
2. Review the target role and its previous trust policy.
3. Identify the external account, role ARN, or wildcard principal in the new policy.
4. Confirm whether the change matches an approved partner, automation, or break-glass workflow.
5. Check for `AssumeRole` activity from the external principal after the change.
6. Review other IAM changes by the same identity: policy attachments, access keys, user creation, and role changes.
7. Review the role's permissions and the resources it can access.

## Evidence

- `event_id`, `event_time`, `user`, `identity_type`, `src_ip`, `account`, and `region`
- `action`, `role_name`, `trust_policy_parsed`, `trust_principal_accounts`, and `trust_external_accounts`
- `trust_wildcard`, `trust_service_principals`, and `trust_federated_principals`
- Previous and current trust policy documents from the request body
- `AssumeRole` and other CloudTrail activity from the external principal
- Change ticket, partner agreement, or automation reference

## Escalation

Escalate when:

- The trust change is not tied to an approved workflow.
- The policy allows `*` or an unknown external account.
- The role has administrative, data-access, or cross-account permissions.
- The external principal assumes the role after the change.
- The same identity made other persistence or logging changes.

## Containment

- Revert the trust policy to the last approved version.
- Remove unauthorized role trust and attached policies.
- Review and revoke sessions and credentials associated with the role.
- Check for role assumption by the external principal before the change was detected.
- Preserve CloudTrail evidence before deleting or modifying the role.
- Add the partner account or workflow to an explicit allowlist after review.

## False positives

- An approved cross-account role for a documented partner or CI/CD account.
- A vendor integration that requires an external AWS principal.
- A break-glass or recovery role with an approved change record.
- A service-linked role or SAML trust that the normalizer did not classify as external.

## Closure

Record the external account, business justification, approval reference, previous policy, role permissions, any assumption activity, and the final decision. Allow-list the specific external account and role, not all external trust changes.

## References

- AWS CloudTrail CreateRole and UpdateAssumeRolePolicy
- AWS IAM role trust policies
- MITRE ATT&CK T1098.003 — Additional Cloud Roles
