# Response — INV-002

## Containment

- Isolate `LAB-EP-01` after preserving volatile evidence.
- Deactivate the new IAM access key.
- Re-enable CloudTrail logging on the affected trail.

## Eradication

- Decode the PowerShell command and remove any dropped payload or persistence.
- Review scheduled tasks, registry autoruns, services, and startup folders on the host.
- Rotate the analyst's password and revoke cloud and directory sessions.
- Remove any unauthorized IAM credentials, policies, or roles.

## Recovery

- Rebuild or restore the host from a trusted image if compromise is confirmed.
- Validate that endpoint and cloud access are restored through approved paths.
- Confirm that CloudTrail is logging and delivering events.

## Verification

- Confirm the host is clean and reintroduced only after validation.
- Confirm the access key is inactive or deleted.
- Confirm CloudTrail logging is restored.
- Confirm no new persistence appears on the host or in AWS.

## Evidence preservation

Preserve the Sysmon process event, Windows logon event, CloudTrail events, the decoded command, and the investigation query output before containment.
