# Benign Baseline Results

## Scope

Sixteen synthetic benign corpora are used to measure false-positive behavior across the detection set.

| Detection | Dataset | Unit | Cases | Matches | FPR |
|---|---|---|---:|---:|---:|
| `DET-IDN-001` | `identity-signin.json` | event | 20 | 0 | 0.00 |
| `DET-IDN-002` | `identity-audit.json` | event | 20 | 0 | 0.00 |
| `DET-END-001` | `endpoint.json` | event | 20 | 0 | 0.00 |
| `DET-CLD-001` | `cloudtrail.json` | event | 20 | 0 | 0.00 |
| `DET-CLD-002` | `cloudtrail.json` | event | 20 | 0 | 0.00 |
| `DET-IDN-003` | `identity-correlation.json` | scenario | 6 | 0 | 0.00 |
| `DET-SAA-001` | `m365-audit.json` | event | 20 | 0 | 0.00 |
| `DET-SAA-001` | `m365-forwarding.json` | event | 20 | 0 | 0.00 |
| `DET-SAA-002` | `github-audit.json` | event | 20 | 0 | 0.00 |
| `DET-NET-001` | `zeek-dns.json` | event | 20 | 0 | 0.00 |
| `DET-NET-002` | `suricata-alerts.json` | event | 20 | 0 | 0.00 |
| `DET-K8S-001` | `kubernetes-audit.json` | event | 20 | 0 | 0.00 |
| `DET-K8S-002` | `falco.json` | event | 20 | 0 | 0.00 |
| `DET-SAA-003` | `identity-saas-correlation.json` | scenario | 6 | 0 | 0.00 |
| `DET-SAA-004` | `identity-saas-delegation.json` | scenario | 10 | 0 | 0.00 |
| `DET-SAA-005` | `identity-saas-mail-access.json` | scenario | 7 | 0 | 0.00 |
| `DET-SAA-006` | `identity-saas-forwarding-chain.json` | scenario | 6 | 0 | 0.00 |

The endpoint baseline also has a before/after tuning result: the initial query matched 8/20 approved management-agent events, and the tuned query matches 0/20. See [`false-positive-tuning.md`](false-positive-tuning.md).

The SaaS forwarding baseline has the same measurement: the initial query matched 8/20 internal forwarding rules, and the tuned query matches 0/20. See [`saas-forwarding-tuning.md`](saas-forwarding-tuning.md).

The identity correlation baseline contains six scenarios with only one step, mismatched users, or activity outside the 30-minute window. The identity-to-SaaS correlation baseline contains six scenarios, the delegation baseline contains ten, and the mail-access baseline contains seven. The forwarding-chain baseline contains six. All five are evaluated at scenario level.

## Baseline contents

- **Identity sign-in:** MFA-satisfied elevated-risk events, non-interactive authentication, low-risk interactive sign-ins, and failed attempts.
- **Identity audit:** application registration and updates, owner removals, and group membership changes.
- **Endpoint:** approved management-agent encoded PowerShell, normal PowerShell, Office helpers, discovery, and nested PowerShell.
- **CloudTrail:** access-key inventory and status updates, trail inventory, and role assumptions.
- **Identity correlation:** sign-in-only, audit-only, mismatched-user, and out-of-window scenarios.
- **Microsoft 365 audit:** file and mail access, mailbox rules without forwarding, mailbox permission changes, Teams activity, and sign-ins.
- **Microsoft 365 forwarding:** internal forwarding rules to the tenant accepted domain.
- **GitHub audit:** pushes, pull requests, issues, member onboarding, team changes, repository changes, and sign-ins.
- **Zeek DNS:** internal, mail, service, reverse, and content-delivery lookups with no long TXT queries.
- **Suricata alerts:** normal network records and policy, scan, denial-of-service, and lower-severity alerts.
- **Kubernetes audit:** unprivileged pod creation, deployment and service changes, inventory, and RBAC operations.
- **Falco:** file, process, network, package, and configuration alerts without terminal-shell events.
- **Identity-to-SaaS correlation:** sign-in-only, rule-only, mismatched-user, out-of-window, normal-sign-in, and non-forwarding-rule scenarios.
- **Identity-to-SaaS delegation:** sign-in-only, permission-only, folder-only, group-only, mismatched-user, out-of-window, normal-sign-in, SendAs-only, low-privilege-folder, and failed-group scenarios.
- **Identity-to-SaaS mail access:** sign-in-only, self-delegation-only, mail-access-only, sign-in-plus-delegation, sign-in-plus-access, delegation-plus-access, and mismatched-mailbox scenarios.
- **Identity-to-SaaS forwarding chain:** sign-in-only, delegation-only, access-only, partial chains, internal forwarding, and normal-sign-in scenarios.

## Approved exceptions

The identity, cloud, and SaaS baselines intentionally exclude the highest-volume approved exceptions:

- successful service principal owner additions
- successful IAM access-key creation by automation
- successful CloudTrail logging changes during maintenance
- internal Microsoft 365 forwarding to the tenant accepted domain (query exclusion)

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

edl detection baseline \
  --id DET-K8S-001 \
  --dataset lab/datasets/synthetic/benign-baseline/kubernetes-audit.json

edl detection baseline \
  --id DET-K8S-002 \
  --dataset lab/datasets/synthetic/benign-baseline/falco.json

edl detection baseline \
  --id DET-SAA-003 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-saas-correlation.json

edl detection baseline \
  --id DET-SAA-004 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-saas-delegation.json

edl detection baseline \
  --id DET-SAA-005 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-saas-mail-access.json

edl detection baseline \
  --id DET-SAA-006 \
  --dataset lab/datasets/synthetic/benign-baseline/identity-saas-forwarding-chain.json

edl detection baseline \
  --id DET-SAA-001 \
  --dataset lab/datasets/synthetic/benign-baseline/m365-forwarding.json
```

The lab test [`tests/lab/test_benign_baselines.py`](../tests/lab/test_benign_baselines.py) asserts the same zero-match results in CI.

## Limitations

- The corpora are synthetic and small.
- Approved owner additions, access-key automation, and logging maintenance are excluded rather than measured.
- The baselines test query behavior, not analyst workload or production prevalence.
- The correlation baselines cover six to ten curated scenarios each; they do not model long-running sequences, event lateness, or mail-flow delivery.
- The SaaS baselines exclude events that intentionally match the detections, such as owner promotions and mail-forwarding rules.
- The SaaS baselines are small and do not measure tenant or organization prevalence.
- The SaaS forwarding tuning study covers one tenant accepted domain and one forwarding-recipient shape.
- The network baselines are small and do not measure sensor coverage, traffic mix, or rule-set changes.
- The Kubernetes baselines are small and do not measure cluster size, workload churn, or admission-policy differences.
