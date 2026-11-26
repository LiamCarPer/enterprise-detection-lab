# Executive Summary — INV-006

A synthetic identity chain shows an administrator granting consent to an external application with an unverified publisher and untrusted redirect URI. Five minutes later, a tenant-wide OAuth permission grant is recorded for the same application.

The consent and grant records confirm the administrator, application, tenant-wide scope, and failed trust checks. The application's intent and any downstream access remain inferred.

## Impact

The synthetic chain represents tenant-wide application access without a risky user sign-in. No real users, tenants, or data are involved.

## Recommendation

Revoke the tenant-wide grant, disable the application service principal, review tenant-wide data access, and add an approved-application inventory with publisher and redirect-URI trust checks.
