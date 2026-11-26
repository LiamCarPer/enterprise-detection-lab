# Executive Summary — INV-005

A synthetic identity chain began with a medium-risk single-factor sign-in. Minutes later, the user consented to the `Contoso Analytics` application with `Mail.Read` and `offline_access` scopes. The application then accessed an executive mailbox.

The consent record confirms the application, user, scopes, and offline access. The mailbox audit record identifies the application as the actor and the executive mailbox as the target. The token exchange and actor intent remain inferred.

## Impact

The synthetic chain represents durable application access to executive mail without a second sign-in prompt. No real users, mailboxes, or data are involved.

## Recommendation

Revoke the consent and refresh tokens, disable the application service principal, review mailbox and file access, and add publisher verification and an approved-application workflow.
