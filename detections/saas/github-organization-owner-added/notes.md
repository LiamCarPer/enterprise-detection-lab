# Detection Notes — DET-SAA-002

## Hypothesis

Organization owners can change repository visibility, manage members and teams, configure secrets and Actions, install apps, and adjust audit settings. An attacker who controls an owner account can promote another account to preserve access after the original account is recovered.

## Query design

- `source = github-audit` restricts the query to the normalized GitHub audit source.
- `action` covers `org.add_member` and `org.update_member`, the events that add or promote a member.
- `role = admin` is the GitHub organization owner permission level.
- `result = success` excludes failed or unknown outcomes.

GitHub records the owner permission as `permission: admin` on membership events. The normalizer maps `permission` to the canonical `role` field and lowercases it.

The native query uses canonical fields. The Sigma rule uses source-level GitHub audit fields and is not executed by the runner.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Establish SaaS organization-owner coverage |

## Test corpus

The package contains 15 synthetic fixtures:

- 5 positive events covering a new owner, a promotion, an API-created owner, a service account promotion, and a rejoining user.
- 5 negative events covering a regular member, a demotion, a removal, a pending invitation, and a repository push.
- 5 benign GitHub events covering pushes, pull requests, team membership, normal member onboarding, and sign-in.

The committed metrics are from local fixture replay, not production traffic.

## Known gaps

- Enterprise owner changes through `business.add_admin` are not normalized.
- Custom organization roles are not represented in the query.
- The query does not correlate owner additions with actor risk, token type, or IP reputation.
- `org.invite_member` does not reliably include the invited role, so pending owner invitations may be missed until acceptance.

## Next tuning step

Normalize enterprise owner events and custom organization roles, then correlate owner changes with token creation, app installation, and repository visibility changes from the same actor.
