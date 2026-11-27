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

It excludes applications in the approved inventory by requiring `approved_app: false`. An application is approved only when its `appId` matches an inventory entry and any supplied redirect URI is on that entry's allowlist.

Finally, it requires one of:

- `publisher_verified: false`
- `redirect_uri_trusted: false`
- `publisher_reputation: untrusted`

This is an event-level detection. It complements `DET-IDN-004`, which correlates a risky user sign-in with a user consent grant.

Publisher reputation is loaded from the tenant configuration. Reputation is keyed by the application owner organization, so an application from a known-untrusted publisher matches even when the publisher is verified and the redirect URI is trusted.

The Sigma rule represents the admin or tenant grant component. Publisher and redirect-URI trust checks are defined in the native query and metadata.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Cover admin consent, tenant-wide grants, and application trust checks |
| 1.1.0 | Add approved-application and publisher-reputation checks | Suppress reviewed applications and flag known-untrusted publishers |

## Test corpus

The package contains 17 synthetic events:

- 6 positive events: admin or tenant consent, or a tenant-wide grant, with an unverified publisher, an untrusted redirect URI, or an untrusted publisher reputation.
- 6 negative events: verified and trusted grants; user consent; failed consent; non-tenant-wide grants; an approved application with weak trust flags.
- 5 benign events: approved admin, tenant, and tenant-wide grants to verified and trusted applications.

## Known gaps

- Publisher verification and redirect-URI trust are normalized fields; they depend on the export and tenant configuration.
- The approved inventory and reputation feed are configuration inputs; stale entries can cause false negatives or false positives.
- The detection does not evaluate application permissions beyond the consent record.
- A verified publisher with trusted reputation can still be malicious or compromised.
- Tenant-wide grants made through other APIs or service principals may not use these operation names.
- The Sigma representation does not include the trust checks.

## Next tuning step

Refresh the approved inventory and publisher reputation feed on a schedule, then correlate consent with subsequent application access.
