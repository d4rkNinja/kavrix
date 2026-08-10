# `@kavrix/client`

Production client-side transport, opaque sync snapshot, and locked/unlocked vault-read
session primitives for Kavrix.

## Control-plane credentials

`ControlPlaneClient` is deliberately a low-level client. It does not persist API
credentials and does not implement an enrollment workflow. Before redeeming an invite or
completing enrollment, the caller must generate and durably protect the independent
32-byte successor credential. An interrupted call must be retried with the exact same
successor bytes; generating another successor can make the exchange unrecoverable.

Successors are accepted as `Uint8Array` values. The client copies that input, encodes the
owned copy into the canonical bearer representation, and wipes the owned bytes after the
request settles. The caller retains ownership of the input and must wipe it when safe.
JavaScript strings are immutable, and Fetch implementations may make internal header and
body copies, so the encoded header string and server-returned invite token cannot be
reliably zeroized. Keep their lifetime short, never log them, and persist them only through
an approved native keychain or protected credential mechanism.

All remote access requires HTTPS. Plain HTTP is accepted only for an explicitly enabled
loopback development server.

## Crash-safe vault initialization

`VaultInitializationCoordinator.begin` generates new independent portable and recovery
keys locally and exposes both once before confirmation. `beginImportedPortable` instead
parses and owns a caller-supplied formatted portable key before consuming IDs or touching
protected storage, generates a fresh independent recovery key, and exposes only that
recovery material once. It never formats or redisplays the imported portable key.

Both paths require canonical re-entry of the exact portable and recovery keys before they
create protected device/session material, write the encrypted retry journal, or call the
bootstrap route. A mismatch terminally wipes the attempt. Once confirmed, both paths use
the same exact encrypted bootstrap body and crash-safe resume transitions; no plaintext
portable, recovery, VRK, or device key enters the journal or network request.

## Online unlock and active session facade

`VaultClientSession` is the production, online-only unlock boundary over a strict
`VaultProfile`. A profile contains only the canonical server URL, vault/device IDs, and
the exact persisted keychain/session locators. Construction requires the same concrete
backing object to implement opaque sync storage and vault reads, preventing reads from a
different cache than the one being synchronized.

Every unlock first loads the protected API session credential, verifies the remote session
and required `sync:read`/`sync:write` scopes, and fetches the vault bound to the profile.
Portable, recovery, passphrase, and remembered-device unlocks accept only one active slot
at the current key version and use the reviewed crypto slot APIs with exact vault, slot,
schema, key-version, and device binding. Mutable secrets loaded or copied by the facade are
wiped on every path. The resulting VRK remains owned by `VaultReadSession`; callers receive
only locked/unlocked status, redacted show projections, safe copy receipts, and sync results.

Authorization loss, rollback, malformed post-sync vault binding, or a key/schema/crypto
version change locks and releases the in-process read/sync/transport graph. A generic HTTP
403 is not sufficient evidence to delete protected device or session material, so deletion
is deliberately left to a separately authenticated device-management flow. Offline,
rate-limit, and server failures remain typed and retryable without exposing server bodies.

This slice does not silently trust an offline cache, automatically sync before show/copy,
persist profiles, or compose native keychain/local-store adapters. Locking drops the graph
that retains the bearer header string, but JavaScript and Fetch may keep immutable string
copies that cannot be reliably zeroized.

## Portable-key validation before enrollment

Invite redemption returns the canonical opaque vault record so the joining device can
validate its portable key before creating a device session. Pass that response and the
formatted portable key to `unlockRedeemedVaultWithPortableKey`. The helper has no network
capability, selects only active portable slots at the vault's current key version, and
authenticates the exact vault/slot/schema/key-version binding. The caller owns the returned
VRK and must zeroize it after use.

Do not call `completeEnrollment` unless this local validation succeeds. Redemption consumes
the invite before validation is possible; an interrupted redemption may be retried only
with the exact persisted invite and enrollment successor while their original authorization
remains valid.

## Redacted show and guarded copy

`VaultReadSession.show` returns the exact decrypted group payload together with the item and
bound template. When both queries identify stored opaque IDs, it reads through `getGroup`
and `getItem` without listing. An opaque-looking name that is not an exact stored ID falls
back to the canonical bounded resolver, preserving ID, alias/slug, name,
case-insensitive, and unique-prefix precedence.

`VaultInteractionService` is the application boundary for terminal show and clipboard copy.
Its show result is validated by `credentialShowProjectionSchema`; sensitive fields,
archived fields, and every item/group note body use exact redaction sentinels. Copy resolves
fields dynamically from canonical definitions, enforces state, repeat index, copy policy,
and production-sensitive authorization, then sends one owned UTF-8 byte array directly to
`SecureClipboardPort`. The byte array is wiped after the clipboard call settles. The return
value contains only a sanitized field label and clear delay.

JavaScript strings already present in decrypted canonical payloads are immutable, and
`TextEncoder` or the platform clipboard implementation may create internal copies that
cannot be reliably zeroized. Kavrix keeps those lifetimes short, never returns copied values,
and wipes every mutable byte array it owns.

This layer does not persist mark-used state for one-time values, write audit events, retain a
reauthentication authorization across processes, provide an interactive ambiguity picker,
or durably compose unlock/local state into the public CLI executable.
