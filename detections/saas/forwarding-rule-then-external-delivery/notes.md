# Detection Notes — DET-SAA-007

## Hypothesis

A forwarding rule proves intent to move mail, but it does not prove that mail left the tenant. A subsequent external delivery seen in Exchange Online message trace confirms that the collection path was used. The sequence is higher fidelity than either event alone and does not depend on the mailbox owner reporting a missing message.

## Query and correlation design

The native query returns candidate events from two sources:

- successful Microsoft 365 inbox rule creation or updates that forward to a domain outside the tenant accepted domains (`forward_external: true`)
- successful Exchange Online message-trace `DELIVER` events with an external recipient (`external_recipient: true`)

`correlation.group_by: [mailbox]` requires both steps to resolve to the same mailbox. Step 1 accepts `New-InboxRule`, `Set-InboxRule`, or `UpdateInboxRules` and requires `result: success` plus `forward_external: true`. Step 2 requires `event_class: deliver`, `result: success`, and `external_recipient: true`. `correlation.window_seconds: 3600` requires delivery at or after the rule and within 60 minutes. The window allows for message-rule propagation and normal transport latency.

Message trace resolves `mailbox` to an internal related recipient when present, otherwise to an internal recipient. A REDIRECT event therefore maps to the original internal mailbox, and a later external DELIVER maps back to the same mailbox through `RelatedRecipientAddress`.

The Sigma rule represents the forwarding-rule component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Confirm external delivery after a forwarding rule |

## Test corpus

The package contains 10 synthetic events across six scenarios:

- 2 positive scenarios with an external forwarding rule followed by an external delivery for the same mailbox within five minutes.
- 2 negative scenarios: delivery to an internal recipient; a failed external transport event instead of a delivery.
- 2 benign scenarios: an external delivery without a rule; a rule without a delivery.

Metrics are scenario-level: 2 positive scenarios, 2 negative scenarios, and 2 benign scenarios.

## Known gaps

- Grouping by `mailbox` assumes the message trace resolves the original mailbox through `RelatedRecipientAddress`; some transport paths may omit it.
- The query does not compare the delivery recipient with the rule's forwarding recipient. An external delivery to any recipient within the window counts.
- Message trace detail retention is often shorter than audit retention, so late rule events may lack matching delivery detail.
- The detection correlates timing, not message identity. It does not confirm that the delivered message was the one selected by the rule.
- Content-level confirmation and data-loss-prevention verdicts remain out of scope.
- The Sigma representation covers only the forwarding-rule component.

## Next tuning step

Join the rule's `forward_to` recipient to the message-trace `RecipientAddress`, then add mailbox-owner confirmation and DLP verdicts for content-level confidence.
