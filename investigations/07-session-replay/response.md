# Response — INV-007

## Containment

- Revoke the user's sessions and refresh tokens.
- Block the second source IP if policy allows.
- Review conditional access and token-protection policy coverage.

## Eradication

- Require credential reset and MFA re-registration if compromise is suspected.
- Review mail, file, and cloud activity from the second IP and session.
- Remove any suspicious mailbox rules, delegation, or application grants.
- Review cloud credentials and access keys created from the session.

## Recovery

- Restore normal access through a trusted device and network.
- Confirm token protection and device compliance controls are applied.
- Monitor the user and source IP for recurrence.

## Verification

- Confirm the session and refresh tokens are revoked.
- Confirm no further sign-ins use the session ID.
- Confirm no downstream mail, file, or cloud actions originated from the second IP.
- Confirm no additional users or sessions share the second IP.

## Evidence preservation

Preserve both sign-in records, the session ID, source IPs, risk detections, device context, investigation query output, and evidence hashes before revoking sessions or changing policy.
