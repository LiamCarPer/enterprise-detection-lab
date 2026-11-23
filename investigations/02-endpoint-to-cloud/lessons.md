# Lessons — INV-002

## Detection gaps

- The encoded PowerShell detection does not correlate with credential access, cloud API activity, or failed logons.
- The failed logon is a separate event with no account-takeover correlation.
- Access key creation and CloudTrail shutdown are separate cloud detections.

## Telemetry gaps

- No EDR process ancestry, script-block logging, or network connection data is linked to the encoded command.
- No shared process, token, or session identifier links the endpoint activity to the CloudTrail identity.
- Windows logon telemetry does not identify the application or credential source that generated the failure.

## Improvements

- Add endpoint-to-cloud correlation for encoded PowerShell followed by new cloud credentials.
- Add script-block logging and decode the command content automatically in the lab.
- Add a correlation detection for access key creation followed by logging shutdown.
- Add host and identity risk context to the investigation query.
