# Crash-resumable device join composition

## Scope

Issue #38 exposes the existing crash-safe join/recovery protocol as the public
`creds device join` command family. The lower-level `VaultJoinCoordinator` and
the production recovery finalizer already implement the security-sensitive
work; this issue adds the correctly named device command without duplicating
successor-token, portable-key, device-slot, or first-sync logic.

## Command contract

```text
creds device join --server <url> --vault <vault-id> [options]
creds device join resume <operation-id> --server <url> --vault <vault-id> [options]
creds device join cancel <operation-id> --server <url> --vault <vault-id>
```

Start accepts a guarded portable-key file or the existing masked/framed invite
and portable-key sources. Resume accepts the same portable-key sources needed
to finish local slot/profile/sync work; cancel removes only a prepared local
journal. The server URL may use `CREDS_SERVER_URL` when the option is omitted,
matching the recovery command.

## Architecture and data flow

1. The command validates server URL, vault ID, source exclusivity, key-file
   safety, stdin framing, and empty-home requirements before secret input.
2. The existing production recovery adapter opens the protected backend and
   global writer lease, creates a `VaultJoinCoordinator` over the protected
   join journal, and reuses exact independent successors on response loss.
3. The coordinator redeems the invite, validates the exact vault binding and
   current active portable slot, and unwraps the VRK locally. Enrollment
   completion is impossible after a wrong or tampered portable key.
4. The recovery finalizer persists/read-backs the protected session and fresh
   device key, publishes the opaque device slot with deterministic identity,
   stores the canonical profile, and runs the first opaque sync.
5. The command renders only the operation, vault, and device IDs. Invite,
   portable-key, successor, session, device-key, VRK, and decrypted records are
   never rendered or placed in ordinary local state.

The lower-level injected `device invite join` adapter remains available for
protocol tests; the public `device join` family is the production composition.

## Failure and replay behavior

- a lost redeem, completion, slot-publication, or sync response can be resumed
  with the same journaled operation and successor identities;
- wrong keys, malformed responses, cross-vault data, unsafe files, missing
  protected storage, and rollback/protocol failures are mapped to generic CLI
  failures;
- the profile is not persisted until remote identity, local unwrap, protected
  storage, and device-slot publication are validated;
- cleanup always closes the environment/backend and wipes mutable key/token
  buffers through the existing recovery adapter.

## Verification

Focused CLI tests cover command naming, exact input forwarding, redacted
receipts, and static public help. Existing production recovery and client join
tests remain the behavioral regression suite for replay, wrong-key,
response-loss, persistence, and first-sync guarantees. The affected CLI
typecheck, build, targeted lint, format, and packed-help checks must pass.
