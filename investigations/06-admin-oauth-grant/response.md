# Response — INV-006

## Containment

- Revoke the tenant-wide grant and refresh tokens.
- Disable or remove the `Contoso Analytics` service principal after preserving evidence.
- Block the application from tenant consent workflows if policy allows.
- Review tenant-wide access to mail, files, and directory data.

## Eradication

- Revoke application credentials and review granted permissions.
- Remove any additional grants, service principals, or role assignments created by the same administrator.
- Review other administrators and applications involved in the same approval pattern.
- Reset administrator credentials if the grant is associated with a suspicious session.

## Recovery

- Restore application access through approved paths.
- Add the application to a tenant deny or approval workflow.
- Monitor the administrator and application for recurrence.

## Verification

- Confirm the tenant-wide grant and refresh tokens are revoked.
- Confirm the application can no longer access tenant data.
- Confirm no additional grants or service principals remain.
- Confirm no other administrators or applications show the same pattern.

## Evidence preservation

Preserve the admin consent event, tenant-wide grant event, trust flags, application owner organization, scopes, investigation query output, and evidence hashes before removing the application or revoking tokens.
