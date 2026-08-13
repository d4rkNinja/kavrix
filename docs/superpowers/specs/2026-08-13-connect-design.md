# Existing-vault connect design

## Scope

Issue #74 adds a command-only `creds connect` workflow for a local installation
that has no profile but still has a valid native or sealed protected backend
containing the device/session credentials for an already-enrolled device.

The command accepts only the non-secret server URL, vault ID, and device ID.
Portable keys, device secrets, session bearers, and decrypted vault material are
never command arguments, output, requests, or durable profile fields.

## Flow

1. Validate the canonical server URL, vault ID, and device ID before protected
   credential access.
2. Open the existing production environment and reject any non-empty profile
   store before loading a session credential.
3. Build the device-scoped session locator, load the protected session secret,
   authenticate it with the server session endpoint, and require `sync:read`
   and `sync:write` for the exact vault/device binding.
4. Fetch and validate the opaque vault record. Select exactly one active device
   key slot for the requested device at the current vault key version. Load the
   matching protected device secret and unwrap the root key locally only as a
   validity check; wipe the secret and root key in `finally` blocks.
5. Persist the canonical non-secret profile, open the per-vault SQLite store,
   and run `SyncEngine` directly with `FetchSyncTransport`. Direct sync is
   required because the normal unlocked read session deliberately requires the
   local vault record, while a fresh connect has not populated that cache yet.
6. Protected rollback state and opaque records are written by the existing sync
   engine. The environment always closes its stores, backend, lease, and other
   resources, including after failed network or validation paths.

Profile persistence precedes synchronization after credentials are locally and
remotely validated. A transient sync failure therefore leaves a valid profile
   and retryable opaque local state; it does not create a second remote vault or
   mutate remote records.

## CLI contract

`creds connect --server <url> --vault <vault-id> --device <device-id> [--json]`

The text result reports only the vault/device IDs. JSON is the same redacted
identity projection. Existing profiles, missing/revoked credentials, wrong
device slots, malformed remote records, and binding mismatches fail closed.

## Verification

Focused coverage proves empty-home connection, exact profile persistence,
opaque sync bootstrap, protected rollback initialization, wrong/missing/revoked
credential failures, profile ambiguity refusal, server/vault/device binding,
resource cleanup, retry-safe profile persistence, and absence of secret canaries
from argv/output/serialized profile state. Affected client, local-store, and CLI
tests plus format, lint, typecheck, build, and audit gates must pass.
