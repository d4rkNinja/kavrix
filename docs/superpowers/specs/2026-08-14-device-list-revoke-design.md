# Device list and revoke composition

## Scope

Issue #39 exposes the existing hash-only device control-plane routes through
the public CLI. The API and Mongo adapter already own device metadata
validation, cursor binding, session invalidation, and opaque persistence. This
change adds the CLI ports, rendering, command descriptors, and the missing
server-side safety policy without duplicating those lower-level contracts.

## Command contract

```text
creds device list --vault <vault-id> [--limit <1..200>] [--cursor <opaque>] [--json]
creds device revoke <device-id> --vault <vault-id> --confirm
```

`list` renders only `PublicDeviceRecord` fields and forwards bounded cursor
options. `revoke` accepts an opaque device ID, requires the exact `--confirm`
acknowledgement before invoking a port, and prints only a fixed success receipt.
Neither command accepts or emits bearer material, token hashes, key material,
or decrypted vault data.

## Revocation policy

The server treats the authenticated device as authorized to revoke either
itself or another device when it has `device:manage`. Self-revocation is
allowed when another active device remains, so a device can be intentionally
retired. An active target that is the last active device is denied with a
generic authorization failure. Already-revoked targets remain idempotent;
missing targets remain not-found. The active-device check and session
invalidation occur in the authorization adapter's transaction. A non-secret
vault-scoped Mongo fence is advanced inside that transaction before the count,
so concurrent requests cannot bypass the last-device rule between a list and a
delete.

The CLI confirmation is deliberately local and explicit; the API remains the
final authorization boundary. A successful revocation invalidates every
session for the target before the response completes. Tests verify that a
revoked bearer cannot authenticate again and that the last active device is
not revoked.

## Data flow and failure behavior

1. The CLI validates the vault ID, device ID, pagination values, and
   confirmation flag before opening production secret backends.
2. The production port loads the protected session, calls the authenticated
   control-plane client, and zeroizes mutable session bytes in `finally`.
3. The API validates and vault-binds the request, strips `tokenHash` before
   returning a page, and maps last-device denial to a generic authorization
   response.
4. Terminal output is sanitized and stable; malformed pages and unsafe
   responses fail closed without reflecting hostile data.

## Verification

Focused CLI and production-port tests cover pagination, malformed public
records, missing confirmation, current-device revocation, last-device denial,
session invalidation, and token/hash redaction. Affected API, schema, client,
typecheck, build, lint, format, and packed-help checks must pass.
