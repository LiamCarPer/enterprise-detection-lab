# Detection Exception Policy

Exceptions are explicit, reviewed records. They are not a way to hide noisy detections or disable a control.

The catalog is [`detections/exceptions.yaml`](../detections/exceptions.yaml), validated by [`schemas/exceptions.schema.json`](../schemas/exceptions.schema.json).

## Exception types

| Type | Meaning |
|---|---|
| `query-exclusion` | A narrow condition is excluded from the detection query. |
| `review-only` | The alert remains active; analysts verify the documented workflow during triage. |
| `maintenance` | A time-bounded operational exception with a change record. |

Only `query-exclusion` changes detection behavior. `review-only` and `maintenance` exceptions document expected activity without suppressing it.

## Required metadata

Every exception must include:

- a stable `EXC-<DOMAIN>-<NNN>-<NNN>` ID
- the affected detection ID
- the type
- a responsible owner
- a specific reason
- a narrow scope
- a change ticket
- creation and expiry dates
- at least one compensating control

Broad wildcards, permanent exceptions, and exceptions that disable an entire detection are not accepted.

## Lifecycle

1. **Request:** open a change record describing the benign behavior.
2. **Review:** the detection owner verifies the scope, risk, and compensating controls.
3. **Record:** add the exception to the catalog and update tests or baselines.
4. **Review:** revalidate before the expiry date.
5. **Expire or renew:** remove the exception when the underlying workflow changes.

Expired exceptions are reported as validation warnings. They do not silently disappear.

## Current exceptions

| Exception | Detection | Type | Scope |
|---|---|---|---|
| `EXC-END-001-001` | `DET-END-001` | Query exclusion | Approved `corpmgmt.exe` parent |
| `EXC-IDN-002-001` | `DET-IDN-002` | Review only | Application onboarding workflows |
| `EXC-CLD-001-001` | `DET-CLD-001` | Review only | IAM onboarding automation |
| `EXC-CLD-002-001` | `DET-CLD-002` | Review only | CloudTrail maintenance |
| `EXC-SAA-001-001` | `DET-SAA-001` | Query exclusion | Internal `example.test` forwarding domain |

## Validation

```bash
edl validate
edl validate --json
```

Validation checks the catalog schema, duplicate exception IDs, detection links, and expired records.

## Review questions

- Is the scope narrower than the detection itself?
- Is there a named owner and a change record?
- Is the exception time-bounded?
- Does a compensating control detect abuse of the exception?
- Would removing the exception create unacceptable analyst noise?
- Is a query change safer than a review-only exception?
