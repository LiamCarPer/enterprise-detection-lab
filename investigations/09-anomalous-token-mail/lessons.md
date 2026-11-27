# Lessons — INV-009

## Detection gaps

- The anomalous-token risk detection is the primary identity signal; mail access raises confidence.
- The detection requires token protection to be missing and may miss tenants without that field.
- The mail-access event does not identify the client application that used the token.
- A legitimate mail client with a risk false positive can produce the same sequence.

## Telemetry gaps

- Token issuance, exchange, and binding details are not modeled.
- The client application and device behind the mail access are not linked.
- Downstream file and cloud activity for the same token is not observed.
- Risk event names and enrichment vary by licensing.

## Improvements

- Add client application and device identity to the mail-access event.
- Correlate the same token with file and cloud access.
- Add token-protection policy coverage and enforcement status.
- Add mailbox-owner confirmation for sensitive mailbox access.
