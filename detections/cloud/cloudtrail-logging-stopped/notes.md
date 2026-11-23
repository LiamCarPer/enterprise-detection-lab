# Detection Notes — DET-CLD-002

## Hypothesis

Stopping CloudTrail logging is a direct defense-evasion action. It is rare in normal operations and should be reviewed even when a change record exists.

## Query design

- `source = aws-cloudtrail` restricts the query to the normalized CloudTrail source.
- `service = cloudtrail.amazonaws.com` scopes the event to CloudTrail management APIs.
- `action = StopLogging` selects logging shutdown.
- `result = success` excludes denied attempts.

The native query uses canonical CloudTrail fields. Trail names and request details remain in `raw` and are not indexed. The Sigma rule uses source-level CloudTrail field names and is not executed by the current runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish cloud logging-integrity coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive StopLogging events across IAM users, root, assumed role, and contractor identities.
- 5 negative events covering denial, StartLogging, trail inventory, selector updates, and deletion.
- 5 benign CloudTrail read and maintenance operations.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- The trail name is not an indexed canonical field.
- The query does not distinguish an organization trail from a single-account trail.
- Overlapping logging coverage is not evaluated.
- Trail deletion and selector changes are separate detections.

## Next tuning step

Index the trail name and evaluate organization-trail coverage. Correlate StopLogging with DeleteTrail, UpdateTrail, IAM changes, and GuardDuty changes in the same window.
