# Detection Notes — DET-IDN-002

## Hypothesis

Adding an owner to a service principal can give an attacker durable control over an application without immediately creating a visible credential. The event is a broad but high-value identity audit signal.

## Query design

- `source = entra-audit` keeps the query on directory audit events.
- `action = Add owner to service principal` selects the ownership operation.
- `result = success` ignores failed attempts.
- `resource.type = ServicePrincipal` avoids application-object and group ownership changes.

The native query uses canonical audit fields. The Sigma rule uses the source-level Entra operation name and is not executed by the current runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish service principal ownership visibility |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive owner additions across different applications and initiating users.
- 5 negative events covering creation, failure, application ownership, removal, and general updates.
- 5 benign directory changes that do not add a service principal owner.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- The event is intentionally broad. Legitimate application onboarding will match.
- No allow-list for approved administrators or automation identities yet.
- No correlation with application creation, credential changes, or consent grants.
- The Sigma rule is not converted or executed in this milestone.

## Next tuning step

Correlate `Add owner to service principal` with `Add service principal`, credential updates, and consent grants within a short window. Add a documented automation allow-list after reviewing real benign ownership workflows.
