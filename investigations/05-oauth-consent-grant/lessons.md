# Lessons — INV-005

## Detection gaps

- A risky sign-in alone is weak; the consent grant is the durable-access step.
- Admin consent is a separate path and is intentionally excluded from this detection.
- The detection does not verify the application publisher, redirect URI, or tenant trust.
- A legitimate application can match if the sign-in risk was elevated.

## Telemetry gaps

- The token exchange between the application and Microsoft 365 is not observed.
- The mailbox audit identifies the application display name, not a verified application ID or publisher.
- Entra audit does not include a full application inventory or an approved-app list.
- Conditional Access and MFA method context are limited.

## Improvements

- Add publisher verification and redirect-URI trust checks.
- Correlate consent with application mail or file access for the same application.
- Add an approved-application inventory and an exception workflow.
- Add coverage for admin consent and tenant-wide grants.
- Track other users who consented to the same application.
