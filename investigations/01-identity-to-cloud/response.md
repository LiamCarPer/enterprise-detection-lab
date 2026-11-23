# Response — INV-001

## Containment

- Revoke the analyst's sessions and refresh tokens.
- Remove the unauthorized service principal owner.
- Deactivate the new IAM access key.
- Re-enable CloudTrail logging on the affected trail.

## Eradication

- Review and remove unauthorized application credentials and permissions.
- Rotate the analyst's password and require MFA re-registration.
- Revert unapproved IAM policy, role, and trust changes.
- Remove any additional access keys or persistence created by the same identity.

## Recovery

- Validate that directory and cloud access are restored through approved paths.
- Confirm that organization-trail logging covers the account.
- Monitor the affected identity and application for recurrence.

## Verification

- Confirm the service principal owner list matches the approved state.
- Confirm the access key is inactive or deleted.
- Confirm CloudTrail is logging and delivering events.
- Confirm no new keys, roles, or consents appear for the same identity.

## Evidence preservation

Preserve the sign-in, audit, and CloudTrail events, the investigation query output, and the evidence hashes before deleting credentials or application objects.
