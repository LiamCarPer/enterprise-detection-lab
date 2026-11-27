# Response — INV-009

## Containment

- Revoke the user's sessions and refresh tokens.
- Review and remove suspicious mailbox rules, delegation, or forwarding changes.
- Block the source IP if policy allows.
- Strengthen token-protection and conditional-access policy coverage.

## Eradication

- Require credential reset and MFA re-registration if compromise is suspected.
- Review mailbox access for sensitive messages and attachments.
- Review cloud credentials and access keys created from the session.
- Review other users and sessions using the same token or IP.

## Recovery

- Restore normal access through a trusted device and client.
- Confirm token-protection and device-compliance controls are applied.
- Monitor the user and mailbox for recurrence.

## Verification

- Confirm the session and refresh tokens are revoked.
- Confirm no further mail access uses the token or IP.
- Confirm no new mailbox rules, delegation, or forwarding remain.
- Confirm no downstream file or cloud activity originated from the session.

## Evidence preservation

Preserve the sign-in risk record, token-protection state, mail-access event, mailbox context, investigation query output, and evidence hashes before revoking sessions or changing policy.
