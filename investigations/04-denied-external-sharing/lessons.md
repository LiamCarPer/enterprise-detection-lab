# Lessons — INV-004

## Detection gaps

- A denial alone is not an exfiltration signal; the delivery and DLP alert provide the evidence that data left the tenant.
- The three-step sequence requires a shared message identifier across the approval, transport, and DLP systems.
- The approval and DLP records share a content scope, so a denial for one dataset is not applied to a different dataset sent to the same recipient.
- The detection does not yet suppress on a later approval for the same content and recipient.
- A retrospective denial is not matched by the ordered sequence.

## Telemetry gaps

- Approval records do not always include a message identifier or a structured content reference.
- DLP alerts describe a policy match, not the data owner’s intent or the full sensitivity of the content.
- The lab does not model approval workflow notifications or whether the requester read the denial.
- Transport and DLP latency are tenant-specific and are represented by simple synthetic timestamps.
- The approval system and mail transport are modeled separately, so clock skew is not measured.

## Improvements

- Replace the synthetic `content_scope` value with a stable dataset or attachment identifier where the systems expose one.
- Add a later-approval check so a superseding decision can be distinguished from the original denial.
- Add mailbox-owner confirmation to close the intent gap.
- Model approval revocations and retroactive decisions as explicit event types.
