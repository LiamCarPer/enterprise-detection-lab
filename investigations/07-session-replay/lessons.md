# Lessons — INV-007

## Detection gaps

- Session ID reuse is the direct link; without it, the IP change alone is weak.
- The detection does not inspect token binding or token-protection status.
- A legitimate network transition can produce the same pattern.
- The sequence ends at the second sign-in, not at an observed mail or cloud action.

## Telemetry gaps

- Device identity and compliance are present but not used in the detection.
- Token exchange and token-protection results are not modeled.
- Downstream application activity for the session is not linked.
- Travel, VPN, and mobile-network context are not available in the lab.

## Improvements

- Add device identity changes and token-protection signals.
- Correlate replay with mailbox, file, and cloud actions from the second IP.
- Add impossible-travel or network-velocity enrichment.
- Track the session across multiple applications and tenants.
