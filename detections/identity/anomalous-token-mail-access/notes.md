# Detection Notes — DET-IDN-008

## Hypothesis

An anomalous-token risk detection on an unprotected sign-in followed by mailbox access can indicate token theft and mail collection. The sign-in alone may be a risk false positive; the mailbox access raises confidence that the session is being used.

## Query and correlation design

The native query returns candidate events from two sources:

- successful Entra sign-ins with `risk_event_types: anomalousToken`, `token_protection_status: notprotected`, and `token_binding_status: unbound`
- successful Microsoft 365 `mail_access` events

`correlation.group_by: [user]` requires both steps to share the identity. `correlation.window_seconds: 1800` requires the mail access at or after the sign-in and within 30 minutes. The mail step does not require a specific mailbox; the group is the user.

The Sigma rule represents the anomalous-token sign-in component. The mail-access correlation is defined in `meta.yaml` and executed by the detection runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Correlate anomalous-token risk with mail access |

## Test corpus

The package contains 16 synthetic events across nine scenarios:

- 2 positive scenarios with an unbound anomalous-token sign-in followed by mailbox access.
- 4 negative scenarios: file access instead of mail; a different risk event type; mail access by a different user; a bound token with mail access.
- 3 benign scenarios: sign-in only; mail access only; normal sign-in plus mail access.

Metrics are scenario-level: 2 positive scenarios, 4 negative scenarios, and 3 benign scenarios.

## Known gaps

- Token protection is not available in every tenant or client; the detection requires `notProtected`.
- Risk event names and enrichment vary by licensing and export shape.
- Mail access by an application may not use the same user principal as the sign-in.
- The detection does not inspect message content or attachment access.
- The detection does not correlate the session with cloud actions.
- The Sigma representation covers only the sign-in component.

## Next tuning step

Add application identity and token-binding signals, then correlate anomalous-token sessions with file and cloud access.
