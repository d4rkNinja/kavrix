# Portable Key and Device Enrollment

> Design status: this document specifies required user and protocol behavior.
> Commands and flows described here are planned until marked verified in
> [implementation-status.md](./implementation-status.md).

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
7. The client uploads only wrapped VRK envelopes, public derivation metadata,
   opaque IDs/versions, and the initial device authentication material required
   by the enrollment protocol.
8. It optionally remembers this device through the native keychain, then clears
   raw keys and transient KEKs best effort.

Cancellation before the server commit leaves no usable remote vault. An
interruption after commit must resume without generating an unrelated second
vault or losing the recovery material confirmation state.

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
2. Over verified HTTPS, it submits the invite to the enrollment endpoint. The
   API hashes and compares it, checks vault/scope/expiry/revocation/rate state,
   and atomically changes one valid invite from unused to consumed.
3. The service issues Device B a new random device token. Only its hash is
   retained server-side. Duplicate display names are resolved without confusing
   device identity; opaque device IDs remain unique.
4. Device B stores the token in native protected storage or an explicitly
   supported protected session channel. Failure to store it must be reported and
   enrollment must remain resumable without logging the token.
5. Device B downloads the portable slot's public algorithm, salt, context,
   versions, and wrapped VRK envelope.
6. It obtains the same portable key locally, derives the KEK locally, and
   authenticates the VRK unwrap. The API never sees the key, KEK, or VRK.
7. On success, it decrypts synchronized records locally and optionally creates a
   device-specific VRK slot protected by the native keychain.
8. It records the highest seen vault/key version in protected local state and
   clears transient key material best effort.

A used, expired, revoked, malformed, or rate-limited invite returns a generic
enrollment failure. A wrong portable key returns a generic unlock failure. The
output must not reveal whether the vault, key prefix, slot, or invite was nearly
correct. Enrollment authorization can succeed before local unwrap; if unwrap or
local persistence then fails, retry uses a bounded resumable protocol rather
than reusing a consumed invite blindly.

## Remember, forget, and revoke

"Remember this device" is optional. It stores an independent device unlock
secret or protected root material only in:

- macOS Keychain;
- Windows Credential Manager or DPAPI-backed secure storage;
- Linux Secret Service/libsecret.

If the keychain is unavailable, locked, or fails its security checks, the CLI
asks for the portable key/passphrase on each unlock. It never writes a plaintext
fallback.

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
same-key unlock on a simulated second device, real platform keychains, resumable
enrollment, portable-slot rotation, device confirmation, last-slot protection,
and post-revocation sync denial.

The end-to-end acceptance case is complete only after Device B decrypts records
created on Device A while the portable key remains absent from every server and
leak-scan surface.
