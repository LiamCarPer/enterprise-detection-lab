# Runbook — Shell Spawned in Container

## Alert meaning

Falco detected an interactive shell inside a container. The shell may be legitimate troubleshooting or an attacker establishing hands-on access.

## Triage

1. Identify the namespace, pod, container, user, process, command line, and time.
2. Confirm whether the shell matches an approved debugging request or a platform workflow.
3. Review Kubernetes audit logs for `pods/exec`, `pods/attach`, and `pods/portforward` requests from the same identity.
4. Check the container image, digest, and deployment owner.
5. Review the pod's recent network connections, file access, and secret mounts.
6. Compare the shell activity with the pod's normal process baseline.
7. Check other pods on the same node and other clusters for similar activity.

## Evidence

- `event_time`, `namespace`, `pod`, `container`, `user`, and `process`
- Falco `rule_name`, `priority`, and `output_fields`
- Kubernetes audit events for exec, attach, and port-forward
- Container image and deployment metadata
- Commands run and files accessed after the shell
- Network connections from the pod
- Change ticket or approved debugging request

## Escalation

Escalate when:

- The shell is not tied to an approved debugging request.
- The pod runs in production or a sensitive namespace.
- The identity is unexpected, compromised, or a service account.
- The shell is followed by credential access, secret reads, or outbound connections.
- Multiple pods or clusters show the same activity.

## Containment

- Terminate the exec session after preserving evidence.
- Delete or isolate the pod if compromise is suspected.
- Revoke the initiating identity's credentials and tokens.
- Rotate secrets mounted by the pod.
- Review and revert unauthorized RBAC or workload changes.
- Preserve node and runtime evidence before cleanup.

## False positives

- Approved debugging with kubectl exec or a platform console.
- Startup scripts or health checks that launch an interactive shell.
- Break-glass troubleshooting during an incident.
- Build or test jobs that run a shell inside a container.

## Closure

Record the business justification, initiating identity, commands run, data accessed, containment, and whether the workflow needs an allow-list. Tune with a namespace, service account, or pod selector, not a global shell exclusion.

## References

- Falco default rules: Terminal shell in container
- MITRE ATT&CK T1059 — Command and Scripting Interpreter
- MITRE ATT&CK T1609 — Container Administration Command
