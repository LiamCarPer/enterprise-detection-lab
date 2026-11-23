# Detection Notes — DET-CLD-001

## Hypothesis

Access key creation is a direct way to obtain durable programmatic access. It is high-signal when viewed with the initiating identity, target user, and subsequent key usage.

## Query design

- `source = aws-cloudtrail` restricts the query to the normalized CloudTrail source.
- `service = iam.amazonaws.com` scopes the event to IAM.
- `action = CreateAccessKey` selects key creation.
- `result = success` excludes denied attempts.

The native query uses canonical CloudTrail fields. Request and response bodies remain in `raw` and are not indexed. The Sigma rule uses source-level CloudTrail field names and is not executed by the current runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish cloud credential persistence coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive key creations across IAM users, automation, contractor, backup, and root identities.
- 5 negative events covering denial, listing, user creation, deletion, and key status changes.
- 5 benign IAM, console, and STS operations.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- The target user and new access key ID are not indexed canonical fields.
- The query cannot distinguish approved onboarding from malicious creation.
- Key usage after creation is not correlated.
- Root key creation and IAM user key creation share the same event shape.

## Next tuning step

Index the target user and access key ID, then correlate CreateAccessKey with subsequent key usage and IAM policy changes. Add a documented automation allow-list after reviewing benign key-creation workflows.
