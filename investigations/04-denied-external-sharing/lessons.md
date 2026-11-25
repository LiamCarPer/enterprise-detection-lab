# Lessons — INV-004

## Detection gaps

- A denial alone is not an exfiltration signal; the delivery and DLP alert provide the evidence that data left the tenant.
- The three-step sequence requires a shared message identifier across the approval, transport, and DLP systems.
- The detection does not compare request scope, so an approval for different content to the same recipient could be mistaken for coverage.
- A retrospective denial is not matched by the ordered sequence.

## Telemetry gaps

- Approval records do not always include a message identifier or a structured content reference.
- DLP alerts describe a policy match, not the data owner’s intent or the full sensitivity of the content.
- The lab does not model approval workflow notifications or whether the requester read the denial.
- Transport and DLP latency are tenant-specific and are represented by simple synthetic timestamps.
- The approval system and mail transport are modeled separately, so clock skew is not measured.

## Improvements

- Add request-scope fields such as dataset name or attachment hash to the approval record.
- Add a later-approval check so a superseding decision can be distinguished from the original denial.
- Add mailbox-owner confirmation to close the intent gap.
- Model approval revocations and retroactive decisions as explicit event types.
