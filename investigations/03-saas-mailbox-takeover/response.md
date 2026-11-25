# Response — INV-003

## Containment

- Revoke the analyst's sessions and refresh tokens.
- Remove the self-delegation and the external forwarding rule.
- Remove any additional mailbox permissions granted by the same identity.
- Preserve the message-trace REDIRECT and external DELIVER records before changing transport controls.

## Eradication

- Review the executive mailbox for forwarding, deletion, and export activity.
- Review the message delivered to `collector@example.org` and identify the exposed content.
- Reset the analyst's password and require MFA re-registration.
- Review mailbox audit settings and forwarding controls on the affected mailbox.
- Remove any other rules or delegate changes created by the same identity.

## Recovery

- Validate that executive mailbox access is restored through approved paths.
- Confirm that external forwarding is blocked or requires approval.
- Monitor the mailbox and analyst identity for recurrence.
- Block the external recipient at the transport layer if policy allows.

## Verification

- Confirm the mailbox permission list matches the approved state.
- Confirm the forwarding rule is removed and no replacement exists.
- Confirm the analyst cannot access the executive mailbox.
- Confirm no additional external recipients or rules appear.
- Confirm message trace shows no further external deliveries tied to the mailbox.

## Evidence preservation

Preserve the sign-in, permission, access, and forwarding events, the message-trace REDIRECT and DELIVER records, the investigation query output, and the evidence hashes before deleting permissions, rules, or transport records.
