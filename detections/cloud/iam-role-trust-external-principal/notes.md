# Detection Notes — DET-CLD-003

## Hypothesis

An IAM role trust policy that allows a wildcard principal or an AWS account outside the recipient account can establish cross-account access, persistence, or a path for an attacker-controlled principal to assume the role.

## Query design

The native query requires:

- `source = aws-cloudtrail`
- `service = iam.amazonaws.com`
- `action` in `CreateRole` or `UpdateAssumeRolePolicy`
- `result = success`
- `trust_external = true`

The CloudTrail normalizer URL-decodes and parses `requestParameters.policyDocument`, extracts AWS account principals, and compares them with `recipientAccountId`. A wildcard AWS principal or an external account sets `trust_external`. Service and federated principals are recorded for triage but do not set the flag by themselves, which avoids alerting on every service-linked role or SAML provider.

The raw policy document remains in `raw` and is not indexed. The Sigma rule represents the CloudTrail operation; the trust-policy decision is defined by the normalizer and native query.

## Tuning history

| Version | Change | Reason |
|---|---|---|
| 1.0.0 | Initial detection | Cover external and wildcard role trust changes |

## Test corpus

The package contains 15 synthetic events, five per fixture class:

- 5 positive events: external account root, external role ARN, wildcard principal, multiple external accounts, and a bare external account ID.
- 5 negative events: same-account trust, failed update, service-principal-only trust, malformed policy document, and an unrelated IAM action.
- 5 benign events: internal role trust changes, service-linked role creation, SAML trust, and a normal `AssumeRole` event.

## Known gaps

- The normalizer evaluates AWS account principals only; federated and service principals are not alerted on by default.
- A cross-account trust can be legitimate and requires an approval or change-record check.
- Policy conditions such as `aws:PrincipalOrgID`, MFA, and source restrictions are not evaluated.
- Malformed policy documents are recorded with `trust_policy_parsed: false` and do not alert.
- The detection observes the trust change, not whether the role was assumed.
- The Sigma representation does not execute the trust-policy parsing.

## Next tuning step

Correlate the trust change with subsequent `AssumeRole` activity from the external account, add organization and partner allowlists, and evaluate policy conditions before alerting.
