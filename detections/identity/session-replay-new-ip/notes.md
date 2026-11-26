# Detection Notes — DET-IDN-006

## Hypothesis

A session established by an interactive MFA sign-in should normally continue from a consistent network context. If the same session ID is used non-interactively from a different source IP with elevated risk, the session may have been replayed.

## Query and correlation design

The native query returns two kinds of Entra sign-in events:

- successful interactive sign-ins that satisfy MFA
- successful non-interactive sign-ins with medium or high risk

Both branches require `session_id`. `correlation.group_by: [user]` keeps the sequence within one identity. Step 1 establishes `session_id` and `src_ip`. Step 2 matches the same `session_id` and declares `match_changed_fields: [src_ip]`, so the source IP must differ. `correlation.window_seconds: 3600` requires the non-interactive use at or after the interactive sign-in and within 60 minutes.

The Sigma rule represents the interactive MFA component. The session-ID and source-IP change correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Detect session reuse from a new IP with elevated risk |

## Test corpus

The package contains 14 synthetic events across eight scenarios:

- 2 positive scenarios with a non-interactive high/medium-risk sign-in that reuses the session from a different IP.
- 3 negative scenarios: same IP; different session; low-risk non-interactive use.
- 3 benign scenarios: interactive only; non-interactive only; normal token refresh from the same context.

Metrics are scenario-level: 2 positive scenarios, 3 negative scenarios, and 3 benign scenarios.

## Known gaps

- A legitimate network transition can change the source IP during a long-lived session.
- A replayed token may use the same IP through a proxy or relay.
- The detection does not inspect device identity, token binding, or token-protection status.
- Session IDs are not guaranteed to be present in every export.
- The detection does not correlate the replay with subsequent mail, file, or cloud access.
- The Sigma representation covers only the interactive MFA component.

## Next tuning step

Add device identity and token-protection signals, then correlate session replay with downstream mail or cloud actions.
