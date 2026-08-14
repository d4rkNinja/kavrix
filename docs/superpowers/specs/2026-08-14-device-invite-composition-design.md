# Device invite command composition

## Scope

Issue #37 adds production composition for issuing, listing, and revoking device
enrollment invites. The API and client already expose the authenticated invite
protocol; this change connects those ports to the CLI and makes the invite
management surface available in the packed command catalog. Invite redemption
remains the follow-on device-join work in issue #38.

## Command contract

The command is:

```text
creds device invite create --vault <vault-id> [--scope <scope...>]
  [--expires-in-seconds <60..86400>] [--stdout] [--json]
creds device invite list --vault <vault-id> [--limit <1..200>]
  [--cursor <opaque>] [--json]
creds device invite revoke <invite-id> --vault <vault-id>
```

Creation defaults to a 600-second lifetime and the least-privilege
`sync:read,sync:write` scope set. Callers may request a subset or add
`device:manage`; the server remains authoritative and rejects scopes the
current device does not hold. The expiry and scope values are parsed through
the canonical API schemas before any authenticated request is made.

The create response contains the invite token because the issuer must transfer
it to the joining device. It is rendered exactly once, only to an interactive
terminal or after an explicit `--stdout` acknowledgement. JSON and text output
contain only the canonical invite ID, one-time token, and expiry; the token is
never persisted, logged, put in argv, or included in list/revoke output.

## Architecture and data flow

1. CLI validates the vault ID, bounded expiry, scopes, and secret-output policy.
2. Production ports load the protected session credential, derive the bearer
   header in memory, and call `ControlPlaneClient.issueInvite`, `listInvitePage`,
   or `revokeInvite`.
3. `ControlPlaneClient` validates the request/response schemas and sends only
   the authenticated opaque HTTP request. The API hashes the newly generated
   token and returns it only in the issuance response.
4. CLI validates the response and renders the one-time receipt. The bearer
   bytes are zeroized by the existing remote-operation boundary.

The internal catalog keeps the existing join descriptor available to focused
tests, while the packed catalog exposes only create/list/revoke until issue #38
promotes the join flow.

## Failure and security behavior

- malformed IDs, scopes, expiry, duplicate scopes, missing options, redirected
  secret output without `--stdout`, and unsupported injected ports fail before
  network access or secret output;
- server authorization, expiry, replay, rate, and revocation policy remains in
  the API; the CLI does not duplicate or weaken it;
- list output is the canonical public invite projection and cannot contain a
  token or token hash;
- malformed responses become generic CLI failures and hostile terminal text is
  sanitized by the existing renderer.

## Verification

Focused CLI tests cover default and explicit issuance options, bounded invalid
input, one-time output authorization, response validation, secret-free list and
revoke behavior, and production-port forwarding/zeroization. The affected CLI
typecheck, build, targeted lint, format, and packed-help smoke checks must pass.
