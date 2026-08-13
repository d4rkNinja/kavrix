# Remember and forget device unlock material

## Scope

Issue #40 adds ergonomic public commands around the existing authenticated
`device-key` slot lifecycle. The cryptographic slot creation, native-keychain
storage, reauthentication, replacement checks, and cleanup already live in
`production/slot-lifecycle.ts`; this issue composes them without creating a
second secret-storage path.

## Command contract

```text
creds device remember [options]
creds device forget <slot-id> [options]
```

`remember` creates one fresh device-key slot for the current profile. Its
random device-unlock secret is generated locally, stored only through the
native `KeychainPort`, read back for verification, and never enters argv,
stdout, the API request, the session locator, or an ordinary file.

`forget` requires the exact opaque device-key slot ID. It uses the existing
disable operation, which removes only that local keychain account. The remote
encrypted slot remains unchanged, and the API session credential remains in
its separate native session account. If the target is the profile's current
slot, an active verified replacement is required before deletion; otherwise
the operation fails closed and retains the keychain entry.

Both commands require the existing explicit reauthentication options. This
prevents an accidental local deletion or slot creation from bypassing the
vault's unlock policy. JSON/text receipts contain only public slot metadata
and an explanation of the local-only effect; no key or session bytes are
rendered.

## Data flow and failure behavior

1. The catalog validates the slot ID and acquires reauthentication through the
   masked, bounded-stdin, protected-file, or native device-key paths already
   used by `key slot`.
2. The production lifecycle loads the protected API session and canonical
   vault, unwraps the root key locally, and checks the authenticated
   `device-key` slot binding.
3. `remember` stores and reads back the generated device secret before
   publishing the encrypted slot; publication failure removes the newly
   written local entry.
4. `forget` deletes only the exact `{vaultId, deviceId, keySlotId}` keychain
   locator after replacement validation. It never calls the API revoke route
   and never deletes the session locator.
5. Every mutable secret buffer is wiped best effort and all opened protected
   resources are closed, including failure and cleanup failures.

## Verification

Focused CLI tests cover operation shaping, explicit slot targeting, redacted
receipts, and help. Existing slot-lifecycle tests cover native storage
round-trip/readback, wrong-key failure, replacement and last-slot guards,
remote-vs-local effects, session/keychain account separation, cleanup, and
secret canaries. Affected typecheck, build, lint, format, and packed-help
checks must pass.
