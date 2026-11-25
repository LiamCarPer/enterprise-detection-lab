# Lessons — INV-003

## Detection gaps

- The event-level forwarding detection does not distinguish a rule creation from a follow-up update.
- The self-delegation and mail-access sequence requires correlation to become high-signal.
- The full chain is split across five detections; `DET-SAA-006` evaluates the four mailbox steps and `DET-SAA-007` confirms external delivery.
- There is no approved-administration baseline for executive mailbox delegation.

## Telemetry gaps

- Exchange message trace is now in scope and confirms that the redirected message was delivered to an external recipient.
- Data-loss-prevention verdicts and content inspection are not available, so the sensitivity of the delivered content is unknown.
- Mailbox-owner confirmation and delegation-ticket context are outside the lab.
- The lab does not model Microsoft 365 audit-pipeline latency or duplicate delivery.
- The source IP is shared across the chain but does not prove a single session or device.

## Improvements

- Join the rule's forwarding recipient to the message-trace `RecipientAddress`.
- Add data-loss-prevention and content-confirmation telemetry to measure what left the tenant.
- Add a rule-update event to the forwarding detection corpus.
- Correlate the chain with mailbox audit settings and external-recipient allow-lists.
- Add an approved mailbox-administration workflow for executive mailboxes.
