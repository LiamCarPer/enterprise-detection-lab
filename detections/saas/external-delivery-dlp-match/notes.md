# Detection Notes — DET-SAA-008

## Hypothesis

Message trace confirms that a message left the tenant, but it does not describe the content. A high-severity Microsoft Purview DLP alert on the same message adds content-level context: a policy matched sensitive information and the message was still delivered externally.

The sequence is stronger than either signal alone. Message trace alone cannot distinguish a routine external reply from an exfiltration path, and a DLP alert alone may describe an internal share, a blocked message, or a message that never left the tenant.

## Query and correlation design

The native query returns candidate events from two sources:

- successful Exchange Online message-trace `DELIVER` events with an external recipient (`external_recipient: true`)
- active high-severity Microsoft Purview DLP alerts for the Exchange workload

`correlation.group_by: [message_id]` and `match_fields: [message_id]` require both steps to resolve to the same message. Message identifiers are lowercased during normalization so case differences between exports do not break the join. Step 1 requires `event_class: deliver`, `result: success`, and `external_recipient: true`. Step 2 requires `event_class: dlp_alert`, `status: active`, `severity: high`, and `workload: Exchange`. `correlation.window_seconds: 1800` requires the alert at or after the delivery and within 30 minutes, which covers normal DLP alert generation latency.

The Sigma rule represents the DLP alert component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Add content-level confirmation to external delivery |

## Test corpus

The package contains 13 synthetic events across seven scenarios:

- 2 positive scenarios where an external delivery and an active high-severity DLP alert share a message identity within three minutes, including a case difference in the message identifier.
- 3 negative scenarios: a resolved alert; an alert for a different message; a medium-severity alert.
- 2 benign scenarios: an external delivery without an alert; an internal delivery with an active high-severity alert.

Metrics are scenario-level: 2 positive scenarios, 3 negative scenarios, and 2 benign scenarios.

## Known gaps

- The join depends on both sources exposing the same `MessageId`; not every DLP policy or export includes it.
- Message identifiers are opaque and are lowercased for matching. This is safe for the modeled exports but should be verified against the tenant's export behavior.
- A DLP alert confirms a policy match, not that the content is sensitive in context or that the sender acted with intent.
- Resolved and dismissed alerts are excluded to prioritize active alerts. An auto-resolved alert may still describe a real policy match and should be reviewed separately.
- DLP policy coverage, severity, and alert latency are tenant-specific.
- The Sigma representation covers only the DLP alert component.

## Next tuning step

Add mailbox-owner confirmation or a reviewer decision so the investigation can distinguish an approved external transfer from an unapproved one.
