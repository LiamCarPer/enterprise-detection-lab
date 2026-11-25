# Lessons — INV-003

## Detection gaps

- The event-level forwarding detection does not distinguish a rule creation from a follow-up update.
- The self-delegation and mail-access sequence requires correlation to become high-signal.
- The full chain is split across four detections; only `DET-SAA-006` evaluates all four steps together.
- There is no approved-administration baseline for executive mailbox delegation.

## Telemetry gaps

- Message-trace and data-loss-prevention telemetry are not available, so outbound delivery is not observed.
- Mailbox-owner confirmation and delegation-ticket context are outside the lab.
- The lab does not model Microsoft 365 audit-pipeline latency or duplicate delivery.
- The source IP is shared across the chain but does not prove a single session or device.

## Improvements

- Add message-trace telemetry to confirm whether forwarded mail left the tenant.
- Add a rule-update event to the forwarding detection corpus.
- Correlate the chain with mailbox audit settings and external-recipient allow-lists.
- Add an approved mailbox-administration workflow for executive mailboxes.
