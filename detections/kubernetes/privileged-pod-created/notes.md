# Detection Notes — DET-K8S-001

## Hypothesis

A privileged container runs without the normal container isolation boundary. It can access host devices, mount host filesystems, change kernel settings, and potentially escape to the node. Privileged pods are sometimes required for platform agents, but they are high-risk when created by an unexpected user or workload.

## Query design

- `source = kubernetes-audit` and `event_class = audit` restrict the query to API server audit events.
- `action = create` and `resource_name = pods` select pod creation.
- `result = success` excludes denied or failed requests.
- `privileged = true` is derived from `requestObject.spec.containers` and `initContainers`.

The normalizer inspects every container and init container for `securityContext.privileged: true`. The Sigma rule uses source-level audit fields and is not executed by the runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish Kubernetes privilege coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive pod creations with privileged containers, privileged init containers, multiple containers, and host namespaces.
- 5 negative events covering unprivileged pods, denied creation, deployment templates, deletion, and a pod without a privileged container.
- 5 benign Kubernetes operations covering application pods, inventory, configuration reads, deployments, and services.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- The detection does not evaluate Linux capabilities, hostPath mounts, hostNetwork, or hostPID separately.
- Admission-controller denials may appear as failed requests and are not alerted.
- Workloads created through controllers may be recorded as deployment or replica-set changes rather than pod creation.
- The privileged flag is only derived when the audit policy includes the request body.
- Approved platform agents need a narrow namespace, service account, or image allow-list.

## Next tuning step

Add capability, hostPath, hostNetwork, and hostPID signals to the normalized event. Correlate privileged pod creation with the creating identity, namespace policy, image provenance, and subsequent exec or node-level activity.
