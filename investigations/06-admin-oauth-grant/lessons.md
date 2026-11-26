# Lessons — INV-006

## Detection gaps

- Admin consent and tenant-wide grants are high-impact even without a risky user sign-in.
- The detection does not verify application permissions beyond the consent record.
- A verified publisher can still be malicious or compromised.
- The detection does not correlate the grant with downstream application access.

## Telemetry gaps

- Entra audit records the grant and trust flags, but not the application's intended behavior.
- Publisher reputation and redirect-URI allowlists are not part of the lab telemetry.
- The application inventory and approval state are not available in the lab.
- Token exchange and application access are not observed for this chain.

## Improvements

- Add an approved-application inventory and a redirect-URI allowlist.
- Enrich with publisher reputation and application risk.
- Correlate tenant-wide grants with downstream mail, file, or directory access.
- Add coverage for service-principal credential and role changes.
