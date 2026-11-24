# Detection Notes — DET-K8S-002

## Hypothesis

An interactive shell inside a container is a hands-on execution signal. It can be legitimate debugging, but it is also a common step after exploitation, credential theft, or lateral movement into a cluster.

## Query design

- `source = falco` and `event_class = runtime_alert` restrict the query to Falco alerts.
- `rule_name = Terminal shell in container` selects the default Falco rule for an interactive shell.

The normalizer maps Falco output fields to canonical namespace, pod, container, user, and process fields. The Sigma rule uses the Falco rule name and is not executed by the runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish Kubernetes execution coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive terminal-shell alerts across bash, sh, zsh, and dash in multiple namespaces.
- 5 negative alerts for file writes, sensitive file reads, outbound connections, untrusted shell rules, and package management.
- 5 benign runtime alerts covering health checks, configuration updates, image builds, and agent reporting.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- Legitimate `kubectl exec` debugging produces the same alert.
- The rule name must match the deployed Falco rule set and language.
- Falco rule coverage depends on the driver, kernel, and container runtime.
- The alert does not show the full command history or session duration.
- A shell can be spawned by a process that Falco does not attribute to a container.

## Next tuning step

Correlate terminal-shell alerts with the initiating Kubernetes audit identity, exec subresource requests, image provenance, and subsequent cluster or cloud activity. Add a namespace or service-account allow-list for approved debugging workflows.
