# INV-001 — Identity Persistence to Cloud Credential Access

## Scenario

A medium-risk single-factor sign-in precedes service principal creation, owner assignment, IAM access key creation, and CloudTrail logging shutdown in the local lab.

## Scope

- Identity: Entra sign-in and audit telemetry
- Cloud: AWS CloudTrail management events
- Investigation window: 2026-11-01 08:45–09:45 UTC

## Hypothesis

An identity compromise may have been used to establish application persistence and then create durable cloud credentials while reducing audit visibility.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 08:55 | entra-signin | e1 | Medium-risk single-factor sign-in for `analyst@example.test` |
| 09:10 | entra-audit | e2 | Service principal `Lab Reporting App` created |
| 09:12 | entra-audit | e3 | Owner added to the new service principal |
| 09:25 | aws-cloudtrail | e4 | IAM access key created for `analyst` |
| 09:30 | aws-cloudtrail | e5 | CloudTrail logging stopped on `lab-trail` |

## Inference boundary

The observed events are synthetic lab records. The attacker narrative is an inference based on the shared `analyst` identity, source IP ranges, and timing. No `AssumeRole` event or explicit token exchange was observed. The investigation does not claim that one actor performed every action.

## Detections linked

- `DET-IDN-001` — successful risky sign-in with single-factor authentication
- `DET-IDN-002` — owner added to a service principal
- `DET-CLD-001` — IAM access key created
- `DET-CLD-002` — CloudTrail logging stopped

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the observed users, identity ARN, and source IPs.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
