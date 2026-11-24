# Runbook — Long TXT DNS Query

## Alert meaning

A DNS TXT query used a name of at least 40 characters. The name may contain encoded data, a tracking identifier, or a legitimate policy lookup.

## Triage

1. Identify the querying host, resolver, query name, query type, and time.
2. Decode or inspect the labels for hex, base32, base64, or high-entropy strings.
3. Check the destination domain age, reputation, and registration data.
4. Count similar queries from the same host and domain over the last hour and day.
5. Review response sizes and TXT record contents where available.
6. Check for subsequent connections to the resolved infrastructure or unusual destinations.
7. Compare with known SPF, DKIM, DMARC, antivirus, and telemetry domains.

## Evidence

- `event_time`, `network.source_ip`, `network.destination_ip`, and `network.destination_port`
- `dns.query_name`, `dns.query_type`, and `dns.query_length`
- Query volume and label structure
- Resolver logs and response data
- Related proxy, firewall, and endpoint events
- Domain registration and reputation data

## Escalation

Escalate when:

- The same host sends many long TXT queries to the same domain.
- Labels contain encoded data or high-entropy strings.
- The domain is newly registered, uncategorized, or hosted on dynamic infrastructure.
- The host contacts the domain's infrastructure after the lookup.
- Other hosts show the same pattern.

## Containment

- Block the domain and destination infrastructure at the resolver and egress controls.
- Isolate the host if compromise is suspected.
- Capture resolver and endpoint evidence before cleanup.
- Review other hosts for the same query pattern.
- Preserve query logs for scope analysis.

## False positives

- SPF, DKIM, and DMARC policy lookups.
- Security and reputation services that encode data in DNS.
- CDN or telemetry domains with long hashed labels.
- Application health checks that use unique query names.

## Closure

Record the query pattern, decoded content, domain ownership, related connections, containment, and whether the activity was approved. Tune with domain-specific allow-lists and volume thresholds, not a blanket TXT exclusion.

## References

- MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS
- Zeek dns.log field reference
