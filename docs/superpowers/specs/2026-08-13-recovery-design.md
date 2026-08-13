# Fresh-home portable-key recovery design (#34)

## Goal

Compose one production recovery flow for an empty local data home. The flow
uses an invite to authorize a new device, authenticates the returned current
portable slot locally, persists only protected session/device material, stores a
canonical profile, initializes the protected sync anchor through the first
opaque sync, and leaves the vault ready for a later portable unlock.

The API and MongoDB receive only bearer credentials in the authorization
headers, the public wrapped-key vault record, and opaque encrypted sync
records. The portable key and unwrapped VRK never enter a request body, local
database, journal, renderer, or log.

## Command surface

The public catalog exposes:

```text
creds recover --server <url> --vault <vault-id> [--key-file <path>]
creds recover resume <operation-id> --server <url> --vault <vault-id> [key source]
creds recover cancel <operation-id> --server <url> --vault <vault-id>
```

The invite and portable key use masked prompts by default. Explicit stdin is
framed and bounded. A protected key file uses the existing guarded file reader
and never places the passphrase in argv or environment. Recovery validates the
canonical server URL, vault ID, local profile count, and key-file filesystem
safety before acquiring secret input.

## Lifecycle

1. The production adapter opens the protected backend and empty-home
   environment under the global writer lease. It rejects any existing profile
   before reading an invite or portable key.
2. `VaultJoinCoordinator.begin` validates the invite/vault binding and durably
   stores independent invite, enrollment-successor, and session-successor
   bytes in the protected join journal. The exact successors are reused on
   replay.
3. `resume` redeems the invite, validates the exact response binding and active
   current portable slot, and unwraps the VRK locally. Only after this succeeds
   does it complete enrollment and store/read back the new API session in
   protected storage.
4. Recovery derives a deterministic non-secret device-slot identity from the
   lifecycle operation. It creates a fresh device key and authenticated device
   slot over the locally unwrapped VRK, stores/read-backs the device key in the
   protected backend, and publishes the opaque slot with the exact deterministic
   idempotency key. Replays first inspect the remote vault and reuse an already
   published slot instead of generating a second one.
5. The adapter persists and reads back the canonical profile, opens the empty
   opaque local store, and runs `SyncEngine.synchronize`. The first run starts
   the protected highest-seen revision at zero and advances it only from the
   authenticated sync cursor. The profile is not persisted before the remote
   device/session and slot state is validated.
6. Cleanup closes the environment/backend and wipes all mutable key, bearer,
   and passphrase byte buffers. Any ambiguous post-enrollment state remains
   resumable; it is never silently deleted.

## Failure and replay policy

- Wrong portable keys, malformed/tampered redemption responses, wrong vaults,
  missing scopes, unsafe key files, missing protected storage, and rollback or
  sync protocol errors are generic failures.
- A failed local portable unwrap never calls enrollment completion.
- A lost redeem or completion response reuses the journaled successors through
  `VaultJoinCoordinator`; it never creates a new device or successor for the
  same operation.
- A lost slot-publication response is reconciled by fetching the vault and
  checking the deterministic slot ID and authenticated device-key unwrap. A
  missing profile or local sync store can therefore be repaired without
  repeating invite redemption.
- No plaintext key or VRK is written to the join journal. The public profile,
  SQLite store, and sync status contain only opaque IDs, ciphertext, cursors,
  and timestamps.

## Out of scope

Unlock-slot listing/disable/revoke and portable-key rotation remain in #35 and
#36. The later device invite/list/revoke command family remains in #37/#38.
This flow does not add backup/restore or plaintext key import.

