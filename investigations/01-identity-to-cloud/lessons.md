# Lessons — INV-001

## Detection gaps

- The risky sign-in detection is single-event and does not correlate with subsequent directory or cloud changes.
- Service principal ownership is a broad audit event with no approval or owner allow-list.
- Access key creation and CloudTrail shutdown are separate detections; there is no cross-domain correlation rule.

## Telemetry gaps

- No `AssumeRole` event was observed, so the identity-to-cloud session link is inferred.
- Conditional Access policy details and MFA method context are limited.
- Email, endpoint, and network telemetry are not linked to the initial sign-in.

## Improvements

- Add a correlation detection for risky sign-in followed by directory persistence.
- Add a correlation detection for access key creation followed by logging shutdown.
- Index the target user and access key ID for faster cloud pivots.
- Add application owner and automation allow-lists after reviewing approved workflows.
- External role trust changes provide a durable path into the account and should be reviewed with any subsequent role assumptions.
