# Detection Notes — DET-SAA-009

## Hypothesis

A denied external-sharing request is a decision, not an event that proves data left the tenant. The detection becomes actionable when the denied recipient later receives a message from the same mailbox and a DLP alert matches that message. The sequence shows that the decision was bypassed and that the delivered content matched a sensitive-content policy.

## Query and correlation design

The native query returns candidate events from three sources:

- ServiceNow approval records with `decision: denied`
- successful Exchange Online message-trace `DELIVER` events with an external recipient
- active high-severity Microsoft Purview DLP alerts for the Exchange workload

`correlation.group_by: [delivery_recipient]` gathers events for the same external recipient. Step 1 requires `event_class: approval` and `decision: denied`, and matches on `mailbox`, `delivery_recipient`, `message_id`, and `content_scope`. Step 2 requires `event_class: deliver`, `result: success`, and `external_recipient: true`, and matches the same `mailbox`, `delivery_recipient`, and `message_id`. Step 3 requires `event_class: dlp_alert`, `status: active`, `severity: high`, and `workload: Exchange`, and matches the same `message_id` and `content_scope`. `correlation.window_seconds: 86400` allows a request to be denied up to a day before the delivery and covers normal DLP alert latency.

The approval step establishes the denied decision, recipient, and content scope. The delivery step narrows that decision to a specific message and mailbox. The DLP step adds content-level context and must match the same content scope, so a denial for one dataset does not cover a different dataset sent to the same recipient.

The Sigma rule represents the denied approval component. The temporal correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Distinguish a denied request from an approved external transfer |

## Test corpus

The package contains 20 synthetic events across eight scenarios:

- 2 positive scenarios where a denied request is followed by delivery to the same mailbox and recipient and a high-severity DLP alert on the same message and content scope.
- 4 negative scenarios: an approved request; a denied request where the DLP alert belongs to a different message; a denied request with delivery but no DLP alert; a denied request where the DLP alert names a different content scope.
- 2 benign scenarios: a denied request without delivery; a delivery and DLP alert without an approval record.

Metrics are scenario-level: 2 positive scenarios, 4 negative scenarios, and 2 benign scenarios.

## Known gaps

- The approval record must carry the message identifier for the three-step join. Many approval workflows do not include it.
- Grouping by `delivery_recipient` can mix requests and deliveries for a shared external recipient; the mailbox, message, and content-scope matches provide the specificity.
- `content_scope` is only as reliable as the approval and DLP mappings. A tenant that does not populate a shared scope value will not get this narrowing.
- A denial may be followed by a later approved request for the same content and recipient. The detection does not yet suppress on a superseding approval.
- A denial may be recorded after the delivery; the ordered sequence will not match a retrospective denial.
- Approval and DLP state can change after the decision or alert. The detection evaluates the committed record, not later updates.
- The Sigma representation covers only the denied approval component.

## Next tuning step

Add a later-approval check so a superseding approval can be distinguished from the original denial.
