# Response — INV-004

## Containment

- Preserve the approval, message-trace, and DLP records before cleanup.
- Recall or remove the external message when the platform supports it.
- Block the external recipient at the transport layer if policy allows.
- Remove unauthorized forwarding or delegation if related activity is found.

## Eradication

- Review the sender's recent mail activity for additional external deliveries.
- Confirm whether a later approval covers the same content and recipient.
- Remove any unauthorized inbox rules or delegate changes.
- Notify the data owner and follow the tenant's incident process for regulated data.

## Recovery

- Confirm that external sharing to the recipient requires approval.
- Restore normal mail flow after the message and policy review.
- Monitor the sender and recipient for recurrence.

## Verification

- Confirm the message is recalled or the exposure is documented.
- Confirm no later approval supersedes the denial.
- Confirm the DLP alert is closed with a disposition.
- Confirm no additional external deliveries share the approval request.

## Evidence preservation

Preserve the approval record, the message-trace delivery, the DLP alert, the investigation query output, and the evidence hashes before changing approval, transport, or retention settings.
