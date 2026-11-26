# Response — INV-005

## Containment

- Revoke the user's consent and refresh tokens.
- Disable or remove the `Contoso Analytics` service principal after preserving evidence.
- Block the application from tenant consent workflows if policy allows.
- Review mailbox and file access by the application.

## Eradication

- Revoke application credentials and review granted permissions.
- Remove any additional permissions, grants, or service principals created by the same actor.
- Reset the user's credentials if the originating sign-in is suspicious.
- Review other users who consented to the same application.

## Recovery

- Restore normal mail and application access through approved paths.
- Add the application to a tenant deny or approval workflow.
- Monitor the user, application, and mailbox for recurrence.

## Verification

- Confirm the consent and refresh tokens are revoked.
- Confirm the application can no longer access the mailbox.
- Confirm no other users or mailboxes are affected.
- Confirm no additional grants or service principals remain.

## Evidence preservation

Preserve the sign-in event, consent event, scopes, application owner organization, mailbox access event, investigation query output, and evidence hashes before removing the application or revoking tokens.
