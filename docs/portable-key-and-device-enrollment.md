# Portable Key and Device Enrollment

> Design status: this document specifies required user and protocol behavior.
> The fresh-home `creds recover` composition is implemented and covered by
> focused production tests; later device-management and rotation flows remain
> planned until marked verified in [implementation-status.md](./implementation-status.md).

## The three credentials are different

Kavrix uses three independent credential classes during enrollment:

| Credential         | Purpose                                            | Where plaintext may exist                                                                      | Server storage                                      |
| ------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Portable vault key | Derives the KEK that unwraps the VRK on any device | Masked local input, dedicated protected file, explicit stdin, or native keychain after consent | Never sent or stored                                |
| Enrollment invite  | Authorizes one new device to enroll                | Creating/joining clients during the explicit flow                                              | Cryptographic hash only; short-lived and single-use |
| Device token       | Authenticates one device's later API requests      | That device's native protected storage and HTTPS authorization header                          | Cryptographic hash only                             |

They are not interchangeable. The portable key must never double as an invite,
device token, account password, API payload, URL parameter, or database value.
Possession of an invite or device token alone does not decrypt the vault.

## Portable key properties

A generated key has 256 bits of CSPRNG entropy and the canonical copy form
`cvk1_<base64url-data-and-checksum>`. The checksum rejects likely transcription
errors but does not authenticate a user. Exact encoding and derivation rules are
defined in [cryptography.md](./cryptography.md).

The same canonical bytes and stored HKDF-SHA-256 slot parameters derive the same
portable KEK on Windows, macOS, and Linux. Parsers do not trim or normalize key
content. Malformed keys are rejected locally, before an API request or unwrap.
A wrong but well-formed key produces only a generic unlock failure after
authenticated unwrapping.

## Allowed and forbidden input channels

Allowed:

- a masked interactive prompt;
- a dedicated portable-key file passed by path;
- explicit `--key-stdin` for headless automation, with bounded input and safe
  TTY/echo checks;
- native OS keychain material after the user explicitly enables "remember this
  device."

Forbidden:

- `--key <value>` or any secret-valued normal flag/positional argument;
- query strings, fragments, or other URLs;
- environment variables by default;
- plaintext config/application-data files;
- clipboard auto-read without an explicit user paste;
- API request or enrollment payload fields containing the key;
- repurposing an SSH private key as the vault key.

Generated keys may be displayed or copied only during explicit creation/export.
Copy is opt-in and auto-clear is best effort. Ordinary status, device, slot, and
dashboard views never render the key.

## Initial device: `creds init`

### Generate a key (recommended)

1. The CLI explains that loss of every unlock/recovery method makes the vault
   unrecoverable and offers a dedicated protected key file.
2. It generates the portable key locally and displays it once only after an
   explicit reveal action. It may copy only after a separate explicit action.
3. The user saves the key. File creation applies the checks below.
4. The CLI removes the displayed/in-flow confirmation copy, then requires the
   user to re-enter the key through a masked prompt or re-import the saved file.
5. It compares the canonical key bytes in constant time. Initialization does not
   continue until possession is proved.
6. The client generates an independent random VRK and recovery key, derives the
   portable and recovery KEKs locally, and creates independent authenticated VRK
   slots.
7. Before the bootstrap request, the client independently generates a random
   256-bit API session credential and durably stores its raw bytes in the native
   keychain under the new vault/device identity. This entry is separate from any
   device-unlock secret or VRK slot.
8. Over verified HTTPS, the client sends that credential once as the bearer for
   `POST /v1/vaults`, together with only the revision-zero encrypted vault,
   wrapped VRK envelopes, public derivation metadata, and first-device metadata.
   The service atomically creates the vault, rollback/sync anchor, first device,
   session, and global credential-hash claim. It never returns the credential.
9. It clears raw keys, the transient bearer copy, and KEKs best effort. The
   durable native-keychain credential remains available for authenticated sync.

Cancellation before the server commit leaves no usable remote vault. An
interruption after commit must resume without generating an unrelated second
vault or losing the recovery material confirmation state. An exact retry uses
the same locally protected bearer and encrypted body; incompatible reuse,
existing vault/device identity, or a credential-hash collision fails closed.
The route does not exist unless the operator explicitly enables the bootstrap
configuration gate. Operators should enable it only for the intended
provisioning window and disable it afterward; source and per-bearer rate limits
still apply while enabled.

The server-side bootstrap/Mongo transaction and the distinct native session
credential adapter are implemented and have real MongoDB replica-set and
Windows Credential Manager tests. Production `creds init --key-file` now
composes the guarded unprotected/passphrase-protected reader and requires an
unbound file for fresh initialization; real macOS Keychain/Linux Secret Service
behavior remains unverified.

### Import an existing key

The user may paste a canonical portable key into a masked prompt or select a
dedicated key file. The client validates syntax/checksum locally, proves the key
by authenticating the expected VRK envelope where one exists, and never uploads
the key. Arbitrary sentences are rejected as portable keys; they belong to an
optional passphrase slot.

## Dedicated portable-key file

An unprotected file has this strict ASCII form:

```text
-----BEGIN CREDVAULT PORTABLE KEY-----
Version: 1
Vault-ID: <opaque-vault-id-or-unbound>
Key-ID: <opaque-key-slot-id-or-unbound>
Key: cvk1_<canonical-key>
-----END CREDVAULT PORTABLE KEY-----
```

`creds key create --file <path>` creates a new file atomically and refuses to
overwrite by default. `--protect-with-passphrase` uses Argon2id plus
XChaCha20-Poly1305; the protected file contains versioned KDF/AEAD metadata and
ciphertext rather than a plaintext `Key` line. The protection passphrase is
masked, is not trimmed, and is never accepted as a normal argument.

Before any read, the client resolves and validates the exact target:

- reject symlinks/reparse-point ambiguity and non-regular files;
- reject files over the small documented format limit before allocation;
- on Unix, require current-user ownership and mode 0600 or stricter;
- on Windows, require an ACL limited to the current user and necessary system
  principals, with inherited broad grants rejected;
- reject duplicate/unknown critical headers, extra documents, malformed line
  endings/encoding, and vault/key binding mismatch;
- do not silently copy the file into application data.

An explicit override may acknowledge a condition that can be assessed safely,
but must not bypass malformed cryptography or identity ambiguity. The user owns
the backup strategy for this file; cloud sync or filesystem backup may copy an
unprotected key beyond the local device.

## Create an enrollment invite on Device A

`creds device invite` is available only to an unlocked, currently authorized
device. The client requests a new invite over authenticated HTTPS. The service:

1. generates or accepts only protocol-defined random invite material;
2. stores a cryptographic hash, vault binding, creator device ID, expiry,
   allowed scope, state, and attempt metadata;
3. returns the plaintext invite exactly once;
4. rate-limits creation and consumption;
5. supports revocation before use.

The default lifetime must be short and configured server-side within a bounded
maximum. Exact duration and entropy are implementation parameters that require
tests and documentation before release; no unsupported value is asserted here.
Invite output is masked/one-time, absent from logs, and never placed in a command
argument. `creds device invite revoke <invite-id>` uses the opaque invite record
ID, not the secret value.

## Join on Device B

Canonical interactive flow:

```text
creds device join --server <url> --vault <vault-id>
```

With a dedicated key file:

```text
creds device join --server <url> --vault <vault-id> --key-file <path>
```

The invite is entered through a masked prompt or explicit `--invite-stdin`.
There is no normal `--invite <value>` flag.

Protocol sequence:

1. Device B validates the server URL, vault ID shape, input bounds, and local
   key-file safety before sending secret authorization material.
2. Device B generates an independent random 256-bit enrollment credential and
   durably protects it in bounded pending-flow state before making the exchange.
   Over verified HTTPS it submits the invite as the bearer credential and the
   new credential in the dedicated redacted `X-Kavrix-Successor-Token` header.
3. The API hashes both credentials, checks vault/scope/expiry/revocation/rate
   state, atomically consumes the invite, and stores only the successor hash. A
   successful response includes the exact canonical public vault record: wrapped
   slots and encrypted vault ciphertext only, bound to the redeemed vault ID.
4. Device B validates that response, selects an active portable slot at the
   current key version, obtains the portable key locally, derives the KEK
   locally, and authenticates the VRK unwrap with the exact vault, slot, schema,
   and key-version binding. The API never sees the portable key, KEK, or VRK.
5. Only after authenticated unwrap succeeds does Device B generate and durably
   protect an independent random 256-bit device-session token. It authenticates
   with the enrollment credential and sends the device token only in the
   dedicated successor header. The service stores only its hash. Neither
   successor is returned by the service or derivable from its parent.
6. Device B reuses an exact persisted successor only to retry an ambiguous
   response. The server rejects reuse of a bearer value across invite,
   enrollment, and device-token classes. Device B stores the final device token
   in native protected storage or an explicitly supported protected session
   channel. Duplicate display names do not affect unique opaque device IDs.
7. After enrollment, Device B decrypts synchronized records locally and may
   create a device-specific VRK slot protected by the native keychain.
8. It records the highest seen vault/key version in protected local state and
   clears transient key material best effort.

A used, expired, revoked, malformed, or rate-limited invite returns a generic
enrollment failure. A wrong portable key or tampered envelope returns one generic
unlock failure and **must not** trigger enrollment completion. The output must
not reveal whether the vault, key prefix, slot, or invite was nearly correct.

Invite consumption necessarily happens before Device B can validate the
portable key because the redeemed response supplies the authenticated wrapped
slot. If local unwrap fails, the invite is already consumed and the enrollment
credential remains bounded by its original expiry, but no device session has
been created. Device B may retry the exact invite/enrollment-successor exchange
within that expiry to recover from an ambiguous response; it must not generate a
different successor for the consumed invite. Abandoning the flow or reaching
expiry requires a newly issued invite. Possession of an expired or consumed
parent alone cannot recover or derive an active successor.

## Fresh-home recovery: `creds recover`

Recovery is the production-composed path for a device with no local profile:

```text
creds recover --server <url> --vault <vault-id>
creds recover --server <url> --vault <vault-id> --key-file <path>
```

The command rejects a non-empty local data home before loading protected
credentials. It then uses the existing crash-safe join journal to persist the
invite/enrollment/session successors, redeems the invite, authenticates an
active current-version portable slot locally, and completes enrollment. Only
after that local authentication succeeds does it generate a fresh device key,
wrap the same VRK into a new device slot, persist the device secret in the
protected keychain, publish the opaque slot revision, and verify the protected
readback. It stores the canonical profile, initializes protected sync state via
the first opaque sync, and clears session/device/root buffers best effort.

`creds recover resume <operation-id>` replays the durable join operation and
finishes an interrupted slot/profile/sync phase. `creds recover cancel
<operation-id>` removes only a prepared local journal and performs no network
request. Both commands still require the canonical server/vault identity so a
local operation cannot be applied to an ambiguous target. Recovery output is
limited to the opaque operation, vault, and device IDs; invite, portable key,
session successor, device secret, VRK, and decrypted records are not placed in
argv, API payloads, logs, or renderer input.

## Remember, forget, and revoke

"Remember this device" is optional. It stores an independent device unlock
secret or protected root material only in:

- macOS Keychain;
- Windows Credential Manager or DPAPI-backed secure storage;
- Linux Secret Service/libsecret.

If the keychain is unavailable, locked, or fails its security checks, the CLI
asks for the portable key/passphrase on each unlock. It never writes a plaintext
fallback.

The device's API session credential is a different native-keychain entry with a
device-scoped `api-session` locator. Deleting a device-unlock entry must not
delete the session credential, and deleting the session credential must not
delete or reinterpret VRK-unlock material. There is no plaintext-file fallback
for either entry class.

The lifecycle operations have intentionally different effects:

| Operation                            | Local keychain material               | Server device token                                    | Other devices/slots                   |
| ------------------------------------ | ------------------------------------- | ------------------------------------------------------ | ------------------------------------- |
| Lock                                 | Retained if remembered                | Unchanged                                              | Unchanged                             |
| Forget/remove local key              | Deleted best effort                   | Still authorized for sync if token retained separately | Unchanged                             |
| Revoke current/other device          | May be removed locally on that device | Server rejects future requests                         | Does not erase already decrypted data |
| Remove a device-specific unlock slot | That slot becomes unusable            | Device token may remain until separately revoked       | Other slots unaffected                |

The UI must explain these distinctions before destructive actions.

## Portable-key rotation

Portable-key rotation changes the wrapping credential, not the data-encryption
keys:

1. Authenticate with an active slot and unwrap the existing VRK locally.
2. Generate or import a replacement portable key and require save/possession
   confirmation.
3. Derive a new portable KEK with a fresh salt and wrap the same VRK into a new
   key version/slot.
4. Fully unwrap and compare the replacement before activation.
5. Publish the new wrapped slot and show per-device confirmation of the new key
   version.
6. Keep the old slot only during an explicitly chosen bounded grace period.
7. Revoke the old slot only after the last-valid-slot check and a clear warning
   for devices not yet updated.

Group/item payloads remain unchanged. If exposure is suspected, also revoke
affected device tokens; rotating the portable slot alone does not revoke API
access or erase plaintext already obtained.

## Failure, audit, and privacy behavior

- Invite creation, revocation, consumption, device enrollment/revocation, slot
  creation/rotation/revocation, remember/forget, and failure classes generate
  encrypted audit details. No audit entry includes credential values, key
  material, invites, or device tokens.
- API logs omit authorization headers and request/response bodies by default.
- Debug mode retains the same redaction rules.
- Ctrl+C, terminal close, normal exit, and fatal paths cancel pending flow state,
  lock, and clear mutable secret buffers best effort.
- Device lists may show opaque ID, encrypted/decrypted local label, created/last-
  seen time, token version, revocation state, and confirmed key version. They
  never show token or portable-key material.
- The service can observe enrollment timing, IP address, device/vault opaque IDs,
  and slot versions. Zero knowledge does not hide this operational metadata.

## Required verification

Release evidence must cover generated/imported keys, canonical/malformed formats,
checksum comparison, protected and unprotected files, Unix modes, Windows ACLs,
symlink/reparse rejection, masked and explicit-stdin paths, absence from argv/
environment/logs/requests/database/completions, atomic invite consumption under
concurrency, expiry/revocation/replay/rate behavior, independent device tokens,
non-derivability of successors from expired or consumed parents, redaction of
the successor header, same-key unlock on a simulated second device, real
platform keychains, resumable enrollment, portable-slot rotation, device
confirmation, last-slot protection, and post-revocation sync denial.

The end-to-end acceptance case is complete only after Device B decrypts records
created on Device A while the portable key remains absent from every server and
leak-scan surface.
