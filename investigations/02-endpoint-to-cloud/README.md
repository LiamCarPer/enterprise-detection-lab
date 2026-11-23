# INV-002 — Endpoint Execution to Cloud Persistence

## Scenario

Encoded PowerShell on `LAB-EP-01` precedes a failed network logon, IAM access key creation, and CloudTrail logging shutdown in the local lab.

## Scope

- Endpoint: Sysmon process creation and Windows Security logon events
- Cloud: AWS CloudTrail management events
- Investigation window: 2026-11-01 09:10–09:40 UTC

## Hypothesis

An endpoint compromise may have provided the credentials or tooling used to establish cloud persistence and reduce audit visibility.

## Observed events

| Time (UTC) | Source | Evidence | Observation |
|---|---|---|---|
| 09:18 | sysmon | e1 | Encoded PowerShell executed on `LAB-EP-01` |
| 09:22 | windows-security | e2 | Failed network logon from `198.51.100.23` |
| 09:25 | aws-cloudtrail | e3 | IAM access key created for `analyst` |
| 09:30 | aws-cloudtrail | e4 | CloudTrail logging stopped on `lab-trail` |

## Inference boundary

The observed events are synthetic lab records. The endpoint-to-cloud link is an inference based on host, user, source IP, and timing. No shared process identifier, token identifier, or cloud session event connects the endpoint activity to the CloudTrail API calls. The failed logon is context, not proof of lateral movement.

## Detections linked

- `DET-END-001` — encoded PowerShell from a non-PowerShell parent
- `DET-CLD-001` — IAM access key created
- `DET-CLD-002` — CloudTrail logging stopped

## Query

`queries/opensearch.json` searches `edl-events-*` across the investigation window and pivots on the host, endpoint user, cloud identity ARN, and source IP.

## Evidence handling

Each event is stored as a small synthetic snapshot in `evidence/`. The SHA-256 hashes are recorded in `meta.yaml`. No production or customer data is present.
