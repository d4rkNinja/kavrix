# Unlock-slot lifecycle design (#35)

## Goal

Compose the command-only unlock-slot lifecycle on top of the existing opaque
vault record and key-slot cryptographic policies. The API receives only the
canonical public vault record and authenticated request metadata; all unwrap,
derivation, and reauthentication work remains local to the CLI process.

## Command surface

```text
creds key slot list [--json]
creds key slot create <portable-key|passphrase|recovery-key|device-key> ...
creds key slot disable <slot-id> ...
creds key slot revoke <slot-id> ...
```

`list` returns only opaque slot metadata: ID, type, lifecycle state, key
version, creation/revocation timestamps, and the public device ID for device
slots. It never renders a derivation object, salt, provider, wrapped-root
envelope, or any secret.

Create/revoke/disable require an explicit reauthentication method. The
remembered device method is available only when explicitly selected; portable,
recovery, and passphrase methods use masked input, bounded stdin, or a guarded
portable-key file. New portable/recovery/passphrase slots wrap the supplied
credential; device slots generate a fresh device secret and store it only in
the protected keychain.

`revoke` is the remote canonical lifecycle transition to `revoked` and always
uses `assertCanRevokeKeySlot`/`revokeKeySlot` before the authenticated
revision-bound API call. `disable` is deliberately local: it removes only the
current device's protected device-slot secret. Non-device slots have no local
secret to disable and must be revoked instead. Disabling or revoking the
profile's remembered device slot requires another active, verified current-
version device slot and moves the profile locator to that replacement.

Remote create and revoke requests carry an opaque encrypted audit sidecar. Its
root-key-encrypted plaintext contains only the action, slot metadata, actor
device ID, resulting state, key version, and timestamp; the API and Mongo
storage validate its vault/revision/AAD binding and commit it atomically with
the slot revision. Local disable has no remote record mutation and therefore
does not send an audit sidecar.

## Lifecycle and cleanup

1. Open the protected backend and leased environment, resolve exactly one
   active profile, load the protected session, and authenticate the session
   binding and required scope.
2. Fetch and schema-validate the current vault record. List stops here.
3. For mutating operations, unwrap the VRK through the explicitly selected
   active current-version slot and keep it only in mutable process memory.
4. Create a fresh authenticated slot envelope, or derive the next revoked
   record through the core policy. Persist a generated device secret before
   publication and verify protected readback. Publish/revoke with a fresh
   idempotency key, then fetch and verify the resulting remote record.
5. Update the local profile only after a replacement device slot is remote and
   its protected secret has been verified. All roots, credential bytes,
   device-secret bytes, session bytes, and bearer buffers are zeroized in
   `finally` blocks. Environment/backend cleanup runs even when factories or
   network operations fail.

The operation does not use the ordinary credential mutation queue: key-slot
updates are revision-bound control-plane mutations, and local opaque cache
refresh remains the responsibility of the next sync. A response-loss retry is
safe at the API boundary because the request uses the existing idempotency key
and the command verifies the fetched canonical record before reporting
success. Portable-key rotation, durable operation journals, and device-token
management remain in #36–#40.

## Adversarial coverage

Focused tests cover safe list projection, all four slot creation paths,
explicit reauthentication, protected device-key readback, wrong-key failure,
last-current-slot rejection, profile replacement when the remembered slot is
removed, response-loss/replay verification, malformed slot metadata,
non-device disable rejection, encrypted audit sidecars that decrypt only with
the local root key, secret canaries absent from published JSON, and
resource/secret cleanup on failures.
