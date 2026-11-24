# Benign Baseline Results

## Scope

Nine synthetic benign corpora are used to measure false-positive behavior across the detection set.

| Detection | Dataset | Unit | Cases | Matches | FPR |
|---|---|---|---:|---:|---:|
| `DET-IDN-001` | `identity-signin.json` | event | 20 | 0 | 0.00 |
| `DET-IDN-002` | `identity-audit.json` | event | 20 | 0 | 0.00 |
| `DET-END-001` | `endpoint.json` | event | 20 | 0 | 0.00 |
| `DET-CLD-001` | `cloudtrail.json` | event | 20 | 0 | 0.00 |
| `DET-CLD-002` | `cloudtrail.json` | event | 20 | 0 | 0.00 |
| `DET-IDN-003` | `identity-correlation.json` | scenario | 6 | 0 | 0.00 |
| `DET-SAA-001` | `m365-audit.json` | event | 20 | 0 | 0.00 |
| `DET-SAA-002` | `github-audit.json` | event | 20 | 0 | 0.00 |
| `DET-NET-001` | `zeek-dns.json` | event | 20 | 0 | 0.00 |
| `DET-NET-002` | `suricata-alerts.json` | event | 20 | 0 | 0.00 |

The endpoint baseline also has a before/after tuning result: the initial query matched 8/20 approved management-agent events, and the tuned query matches 0/20. See [`false-positive-tuning.md`](false-positive-tuning.md).

The correlation baseline contains six scenarios with only one step, mismatched users, or activity outside the 30-minute window. It is evaluated at scenario level.

## Baseline contents

- **Identity sign-in:** MFA-satisfied elevated-risk events, non-interactive authentication, low-risk interactive sign-ins, and failed attempts.
- **Identity audit:** application registration and updates, owner removals, and group membership changes.
- **Endpoint:** approved management-agent encoded PowerShell, normal PowerShell, Office helpers, discovery, and nested PowerShell.
- **CloudTrail:** access-key inventory and status updates, trail inventory, and role assumptions.
- **Identity correlation:** sign-in-only, audit-only, mismatched-user, and out-of-window scenarios.
- **Microsoft 365 audit:** file and mail access, mailbox rules without forwarding, mailbox permission changes, Teams activity, and sign-ins.
- **GitHub audit:** pushes, pull requests, issues, member onboarding, team changes, repository changes, and sign-ins.
- **Zeek DNS:** internal, mail, service, reverse, and content-delivery lookups with no long TXT queries.
- **Suricata alerts:** normal network records and policy, scan, denial-of-service, and lower-severity alerts.

## Approved exceptions

The identity and cloud baselines intentionally exclude the highest-volume approved exceptions:

- successful service principal owner additions
- successful IAM access-key creation by automation
- successful CloudTrail logging changes during maintenance

Those events match the current detection queries and require an allow-list or a change-control workflow. They are documented in the detection runbooks. The endpoint baseline includes its main approved exception because that exception was specific enough to tune safely.

## Reproduce

```bash
make lab-up
make lab-bootstrap

edl detection baseline \
  --id DET-IDN-001 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-signin.json

edl detection baseline \
  --id DET-IDN-002 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-audit.json

edl detection baseline \
  --id DET-CLD-001 \
  --dataset lab/datasets/synthetic/benign-baseline/cloudtrail.json

edl detection baseline \
  --id DET-CLD-002 \
  --dataset lab/datasets/synthetic/benign-baseline/cloudtrail.json

edl detection baseline \
  --id DET-IDN-003 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-correlation.json

edl detection baseline \
  --id DET-SAA-001 \
  --dataset lab/datasets/synthetic/benign-baseline/m365-audit.json

edl detection baseline \
  --id DET-SAA-002 \
  --dataset lab/datasets/synthetic/benign-baseline/github-audit.json

edl detection baseline \
  --id DET-NET-001 \
  --dataset lab/datasets/synthetic/benign-baseline/zeek-dns.json

edl detection baseline \
  --id DET-NET-002 \
  --dataset lab/datasets/synthetic/benign-baseline/suricata-alerts.json
```

The lab test [`tests/lab/test_benign_baselines.py`](../tests/lab/test_benign_baselines.py) asserts the same zero-match results in CI.

## Limitations

- The corpora are synthetic and small.
- Approved owner additions, access-key automation, and logging maintenance are excluded rather than measured.
- The baselines test query behavior, not analyst workload or production prevalence.
- The correlation baseline covers six curated scenarios; it does not model long-running sequences or event lateness.
- The SaaS baselines exclude events that intentionally match the detections, such as owner promotions and mail-forwarding rules.
- The SaaS baselines are small and do not measure tenant or organization prevalence.
- The network baselines are small and do not measure sensor coverage, traffic mix, or rule-set changes.
