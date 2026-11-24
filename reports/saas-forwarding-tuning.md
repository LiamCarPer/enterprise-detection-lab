# False-Positive Tuning: External Mail Forwarding

## Summary

`DET-SAA-001` was tuned after evaluating it against a 20-event synthetic Microsoft 365 forwarding baseline. The initial query matched eight internal forwarding rules. The tuned query uses the configured accepted-domain list and matches none of the internal forwarding events while preserving all positive fixtures.

| Version | Baseline events | Matches | False-positive rate | Positive fixtures |
|---|---:|---:|---:|---:|
| 1.0.0 — initial | 20 | 8 | 0.40 | 5 / 5 |
| 1.2.0 — tuned | 20 | 0 | 0.00 | 5 / 5 |

## Baseline

[`lab/datasets/synthetic/benign-baseline/m365-forwarding.json`](../lab/datasets/synthetic/benign-baseline/m365-forwarding.json) contains 20 synthetic Microsoft 365 events:

- 8 internal forwarding rules to `example.test` shared mailboxes
- 12 benign file, mail, Teams, and sign-in events without forwarding

The baseline is separate from the detection fixture corpus. Its purpose is to expose plausible internal forwarding activity that a broad detection would otherwise flag.

## Tuning change

The normalizer now extracts every forwarding recipient, computes `forward_domains`, and sets `forward_external` by comparing those domains with `EDL_ACCEPTED_MAIL_DOMAINS`. The tuned query requires an external recipient:

```json
{
  "term": {
    "forward_external": true
  }
}
```

The accepted-domain list is configured in `.env`:

```bash
EDL_ACCEPTED_MAIL_DOMAINS=example.test
```

The before query is preserved in [`queries/opensearch-before.json`](../detections/saas/inbox-rule-mail-forwarding/queries/opensearch-before.json) for reproducibility. The final query remains in `queries/opensearch.json`.

## Trade-off

The exclusion is based on the configured recipient domains. It reduces noise from approved internal forwarding, but an attacker could use a compromised internal account as the forwarding destination. The exclusion is recorded as [`EXC-SAA-001-001`](../detections/exceptions.yaml) with a one-year expiry, owner, change ticket, and compensating controls. The next step is to load accepted domains from a versioned tenant configuration and review internal forwarding through mail-flow and data-loss-prevention controls.

## Reproduce

```bash
make lab-up
make lab-bootstrap

# Before tuning
edl detection baseline \
  --id DET-SAA-001 \
  --dataset lab/datasets/synthetic/benign-baseline/m365-forwarding.json \
  --query queries/opensearch-before.json

# After tuning
edl detection baseline \
  --id DET-SAA-001 \
  --dataset lab/datasets/synthetic/benign-baseline/m365-forwarding.json
```

The lab test [`tests/lab/test_benign_baseline.py`](../tests/lab/test_benign_baseline.py) asserts the same before/after counts in CI.

## Limitations

- The baseline is synthetic and covers one tenant domain; it is not a production benign corpus.
- The measurement covers one SaaS detection, not the full detection set.
- Domain matching covers every recipient parsed from `Parameters` and `OperationProperties`; source shapes can vary by client and workload.
- The exclusion would hide an internal-recipient attack that uses the accepted domain.
- The baseline does not model delegated mailbox administration or mail-flow rules.
