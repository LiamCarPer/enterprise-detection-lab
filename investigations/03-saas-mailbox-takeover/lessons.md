# Lessons — INV-003

## Detection gaps

- The event-level forwarding detection does not distinguish a rule creation from a follow-up update.
- The self-delegation and mail-access sequence requires correlation to become high-signal.
- The full chain is split across six detections; `DET-SAA-006` evaluates the four mailbox steps, `DET-SAA-007` confirms external delivery, and `DET-SAA-008` adds content-level context from DLP.
- There is no approved-administration baseline for executive mailbox delegation.

## Telemetry gaps

- Exchange message trace is now in scope and confirms that the redirected message was delivered to an external recipient.
- A DLP alert now matches the delivered message, but it reports a policy match rather than the full content or the data owner’s intent.
- Mailbox-owner confirmation and delegation-ticket context are outside the lab.
- The lab does not model Microsoft 365 audit-pipeline latency or duplicate delivery.
- The source IP is shared across the chain but does not prove a single session or device.

## Improvements

- The forwarding rule and message-trace delivery now match on recipient and the external delivery and DLP alert match on message identity.
- Add mailbox-owner confirmation and an approval decision so the chain can distinguish approved sharing from exfiltration.
- Add a rule-update event to the forwarding detection corpus.
- Correlate the chain with mailbox audit settings and external-recipient allow-lists.
- Add an approved mailbox-administration workflow for executive mailboxes.
