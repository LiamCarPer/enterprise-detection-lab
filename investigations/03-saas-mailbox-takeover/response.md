# Response — INV-003

## Containment

- Revoke the analyst's sessions and refresh tokens.
- Remove the self-delegation and the external forwarding rule.
- Remove any additional mailbox permissions granted by the same identity.

## Eradication

- Review the executive mailbox for forwarding, deletion, and export activity.
- Reset the analyst's password and require MFA re-registration.
- Review mailbox audit settings and forwarding controls on the affected mailbox.
- Remove any other rules or delegate changes created by the same identity.

## Recovery

- Validate that executive mailbox access is restored through approved paths.
- Confirm that external forwarding is blocked or requires approval.
- Monitor the mailbox and analyst identity for recurrence.

## Verification

- Confirm the mailbox permission list matches the approved state.
- Confirm the forwarding rule is removed and no replacement exists.
- Confirm the analyst cannot access the executive mailbox.
- Confirm no additional external recipients or rules appear.

## Evidence preservation

Preserve the sign-in, permission, access, and forwarding events, the investigation query output, and the evidence hashes before deleting permissions or rules.
