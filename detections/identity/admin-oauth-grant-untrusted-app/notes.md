# Detection Notes — DET-IDN-005

## Hypothesis

Admin consent and tenant-wide OAuth grants create durable access for every user in the tenant. When the application has an unverified publisher or an untrusted redirect URI, the grant is high risk even without a risky user sign-in.

## Query design

The native query requires a successful Entra audit event that is one of:

- `Consent to application`
- `Add OAuth2PermissionGrant`
- `Add delegated permission grant`

It then requires one of:

- `consent_type: admin`
- `consent_type: tenant`
- `tenant_wide: true`

Finally, it requires one of:

- `publisher_verified: false`
- `redirect_uri_trusted: false`

This is an event-level detection. It complements `DET-IDN-004`, which correlates a risky user sign-in with a user consent grant.

The Sigma rule represents the admin or tenant grant component. Publisher and redirect-URI trust checks are defined in the native query and metadata.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Cover admin consent, tenant-wide grants, and application trust checks |

## Test corpus

The package contains 15 synthetic events, five per fixture class:

- 5 positive events: admin or tenant consent, or a tenant-wide grant, with an unverified publisher or untrusted redirect URI.
- 5 negative events: verified and trusted grants; user consent; failed consent; non-tenant-wide grants.
- 5 benign events: approved admin, tenant, and tenant-wide grants to verified and trusted applications.

## Known gaps

- Publisher verification and redirect-URI trust are normalized fields; they depend on the export and tenant configuration.
- The detection does not evaluate application permissions beyond the consent record.
- A verified publisher can still be malicious or compromised.
- Tenant-wide grants made through other APIs or service principals may not use these operation names.
- The Sigma representation does not include the trust checks.

## Next tuning step

Add an approved-application inventory and a redirect-URI allowlist, then enrich with application risk and publisher reputation.
