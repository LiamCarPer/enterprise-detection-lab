# Runbook — Privileged Pod Created

## Alert meaning

A pod was created successfully with at least one privileged container. Privileged containers can access host devices and kernel capabilities and can be used to escape container isolation.

## Triage

1. Identify the creating user or service account, namespace, pod name, image, source IP, and time.
2. Confirm whether the pod is an approved platform agent or a documented debugging task.
3. Review the pod specification for hostNetwork, hostPID, hostPath mounts, added capabilities, and service account tokens.
4. Check the image registry, tag, digest, and signature.
5. Review the creating identity's recent Kubernetes and cloud activity.
6. Check what the pod did after creation: exec, file access, network connections, and mounted secrets.
7. Inspect node-level logs and other pods on the same node.

## Evidence

- `event_time`, `user`, `src_ip`, `namespace`, `pod`, and `resource_name`
- `privileged`, `response_status`, and `audit_stage`
- Raw `requestObject` for the full pod specification
- Image, service account, and volume definitions
- Related exec, attach, and port-forward audit events
- Node logs and runtime alerts
- Change ticket or approved debugging request

## Escalation

Escalate when:

- The creator is not a platform administrator or approved automation identity.
- The namespace is production, kube-system, or another sensitive scope.
- The pod uses hostNetwork, hostPID, hostPath, or added capabilities.
- The image is unsigned, unexpected, or from a public registry.
- The pod is followed by exec, secret access, or outbound connections.

## Containment

- Delete the pod after preserving the audit record and pod specification.
- Cordon or isolate the node if escape is suspected.
- Revoke the creating identity's credentials and tokens.
- Review and revert RBAC, admission-policy, or namespace changes.
- Preserve node and runtime evidence before cleanup.

## False positives

- Approved debugging or node-level troubleshooting pods.
- Platform agents for storage, networking, or security that require privileged access.
- CI automation with a documented privileged build task.
- Break-glass troubleshooting during an incident.

## Closure

Record the business justification, approver, image provenance, pod activity, node impact, containment, and whether the workload was allow-listed. Prefer namespace, service-account, and image-scoped exceptions over a blanket privileged-pod exclusion.

## References

- Kubernetes Pod security context
- MITRE ATT&CK T1610 — Deploy Container
- MITRE ATT&CK T1611 — Escape to Host
