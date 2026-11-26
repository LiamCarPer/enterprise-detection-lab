# Lessons — INV-008

## Detection gaps

- The country change is the primary signal; the second sign-in's high risk raises confidence.
- VPN, corporate proxy, or mobile-network egress can change the apparent country.
- The detection does not calculate distance or travel speed.
- It does not require a device change or token-protection signal.

## Telemetry gaps

- Location enrichment can be stale or inaccurate.
- Travel bookings and VPN inventory are not available.
- Downstream mail, file, and cloud activity for the second session is not linked.
- Token exchange and token-protection results are not modeled.

## Improvements

- Add travel distance and network-velocity calculations.
- Enrich with VPN and corporate-egress inventory.
- Correlate the second sign-in with mailbox, file, and cloud actions.
- Add device and token-protection signals.
