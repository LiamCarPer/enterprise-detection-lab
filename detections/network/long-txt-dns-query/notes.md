# Detection Notes — DET-NET-001

## Hypothesis

DNS tunneling tools encode data in query labels. TXT queries are attractive because they can return larger responses, and long names provide space for encoded payloads. A long TXT label is not proof of tunneling, but it is a useful first-stage signal when paired with volume, repetition, and destination reputation.

## Query design

- `source = zeek` and `event_class = dns` restrict the query to DNS observations.
- `dns.query_type = TXT` selects TXT lookups.
- `dns.query_length >= 40` measures the full query name, not a single label.

The normalizer stores the query name, query type, and computed query length. Zeek DNS events are classified from `_path`. The Sigma rule uses the raw Zeek field and a regular expression because Sigma has no length operator.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish network exfiltration coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive long TXT queries using hex, base32, base64, and mixed labels.
- 5 negative events covering long A and AAAA queries, short TXT queries, and a TXT query below the threshold.
- 5 benign DNS lookups for intranet hosts, mail exchangers, DMARC policy, and content delivery.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- Length alone does not distinguish encoded payloads from legitimate long names.
- The query does not measure entropy, label count, response size, or query volume.
- Suricata DNS events are not covered by this query.
- A tunnel can use short labels and many queries instead of long labels.
- Recursive resolver caching and client-side DNS security can change visibility.

## Next tuning step

Add a volume and entropy signal over a time window, include Suricata DNS telemetry, and correlate long TXT lookups with the destination resolver and subsequent connections. Baseline known SPF, DKIM, DMARC, and reputation domains before raising severity.
