# Cryptography

> Design status: this document is the cryptographic contract for the initial
> implementation. It has not yet received an independent security review and
> does not imply that the described code exists. Consult
> [implementation-status.md](./implementation-status.md).
>
> Pre-release compatibility: Kavrix has not published or released a portable
> key-file format and has produced no supported user artifacts. No compatibility
> is promised before the first release. The canonical version 1 format described
> here becomes stable only when that release is published.

## Design goals

Kavrix uses envelope encryption so unlock credentials can change without
re-encrypting every credential. The API and MongoDB receive only authenticated
ciphertext, wrapped keys, public derivation parameters, opaque identifiers, and
minimal synchronization metadata.

The design deliberately separates four concerns:

1. User-provided unlock material derives a Key Encryption Key (KEK).
2. A KEK wraps a randomly generated Vault Root Key (VRK) in an independent slot.
3. The VRK wraps random group keys; group keys wrap random item keys.
4. Item and attachment keys encrypt application payloads.

Unlock material never directly encrypts credential payloads. All cryptographic
operations must go through small, version-aware APIs that require the caller to
provide typed context; application code must not assemble nonces or AAD ad hoc.

## Primitive suite: version 1

| Purpose                           | Algorithm and parameters                                                                                                                                                      |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Randomness                        | Operating-system CSPRNG exposed through the reviewed runtime/library                                                                                                          |
| Application AEAD and key wrapping | XChaCha20-Poly1305-IETF from standard `libsodium-wrappers` 0.8.4, 256-bit key, 192-bit fresh random nonce, 128-bit tag                                                        |
| Attachment content                | libsodium `crypto_secretstream_xchacha20poly1305`, independent 256-bit attachment key, public stream header, ordered authenticated chunks, required final tag                 |
| Portable-key KEK                  | HKDF-SHA-256, 256-bit random per-slot salt, 256-bit output, info `credvault/v1/portable-key-wrap`                                                                             |
| Recovery-key KEK                  | HKDF-SHA-256, 256-bit random per-slot salt, 256-bit output, info `credvault/v1/recovery-key-wrap`                                                                             |
| Device-key KEK                    | HKDF-SHA-256, 256-bit random per-slot salt, 256-bit output, info `credvault/v1/device-key-wrap`                                                                               |
| Passphrase KEK                    | Asynchronous Node 24 `node:crypto` `argon2("argon2id", ...)`, Argon2 v=0x13, random 128-bit salt, 256-bit output; floor m=65536 KiB, t=3, p=4; parameters serialized per slot |
| Portable-key checksum             | SHA-256 over a domain-separated, versioned byte string, truncated to 40 bits; typo detection only                                                                             |
| Keys                              | Independent random 256-bit VRK, group, item, attachment, device, portable, and recovery keys                                                                                  |

HKDF follows [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
The Argon2id floor is the memory-constrained recommendation in
[RFC 9106 section 4](https://datatracker.ietf.org/doc/html/rfc9106#section-4):
64 MiB, three passes, four lanes, a 128-bit salt, and a 256-bit output. New
passphrase slots should calibrate upward on the target device while never going
below that floor. Stored parameters, not current defaults, govern later unlocks.

XChaCha20-Poly1305 is selected because its 192-bit nonce supports safe random
nonce generation without maintaining a global nonce counter. The implementation
uses the standard `libsodium-wrappers` 0.8.4 package (not
`libsodium-wrappers-sumo`) and the IETF XChaCha construction, not a locally
implemented cipher. Attachment streaming uses the secretstream API exposed by
the same standard package. Libsodium documents the AEAD construction at
[XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
and the streaming construction at
[secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream).

Passphrase derivation uses only the asynchronous `crypto.argon2`; the engine
contract is `>=24.12.0 <25 || >=25.1.0`. `crypto.argon2` was added in v24.7.0 and
marked stable in 24.19 by
[`doc,crypto: mark argon2 and encap/decap as stable`](https://github.com/nodejs/node/commit/7bb6dab70c5ad2a8585c26a3f1cd1da2907f33ee),
so releases between those two points expose the primitive under an
active-development label. The floor is therefore set by the local store rather
than by this module: `DatabaseSync.enableDefensive` was added in v25.1.0 and
backported to v24.12.0, which is also why 25.0.x is excluded. Because the range
admits runtimes where Argon2 predates the stability marking, the CLI probes for
the primitive at startup and fails closed instead of trusting the version string
alone; see `apps/cli/src/runtime-preflight.ts`. Kavrix still treats the Node call
signature as an adapter, persists its own versioned Argon2 parameter schema, runs
RFC vectors and serialized-parameter compatibility tests across the supported
range, and does not call the synchronous variant. A separate native `argon2`
package is excluded to avoid additional binary and install-script risk.

These are initial choices, not claims of everlasting suitability. Any change
requires a new algorithm/envelope version, migration plan, compatibility tests,
and security review. Existing metadata must never be reinterpreted under a new
algorithm.

## Portable key format

A generated portable key contains exactly 32 random bytes. Its copy form is:

```text
cvk1_<base64url-no-padding(raw-key || checksum)>
```

For version 1:

- `raw-key` is 32 CSPRNG bytes.
- `checksum` is the first five bytes of
  `SHA-256("credvault/portable-key-checksum/v1" || 0x00 || raw-key)`.
- The prefix is lowercase ASCII and part of the version dispatch.
- The suffix is canonical unpadded base64url. Alternative alphabets, padding,
  embedded whitespace, Unicode lookalikes, leading/trailing text, and
  non-canonical encodings are rejected.
- The decoded suffix is exactly 37 bytes. Parsers enforce an input-size limit
  before decoding and compare the checksum in constant time.

The checksum detects transcription mistakes; it is neither a password hash nor
an authenticator. A correct key is validated only when XChaCha20-Poly1305
authenticates the VRK unwrap. No reversible verifier or hash usable as an unlock
substitute is stored.

Copy/paste semantics are byte-stable across Windows, macOS, and Linux. The
interactive parser may consume the terminal's line terminator but must not trim,
normalize, case-fold, or rewrite the key itself.

## Key hierarchy

```text
portable key  --HKDF-SHA-256--> portable KEK --+
passphrase    --Argon2id------> passphrase KEK | independently wrap the same VRK
recovery key  --HKDF-SHA-256--> recovery KEK   |
device key    --HKDF-SHA-256--> device KEK ----+
                                                  |
                                                  v
                                      random 256-bit VRK
                                                  |
                                   wraps one random group key
                                                  |
                                    wraps one random item key
                                                  |
                                  encrypts one item payload

separate random attachment key -> authenticated streaming/chunk encryption
```

Keys at every level are independently random. Deriving group or item keys from
the portable key, passphrase, VRK, object IDs, or one another is forbidden. This
keeps compromise and rotation scopes explicit.

The VRK exists only in client memory while needed. A group key can unwrap only
item keys in its group. An item key encrypts the complete item payload,
including values, item-only definitions, notes, and sensitive metadata. Group
payloads, preferences, history/audit payloads, and attachments use dedicated
payload/key contexts; key reuse across incompatible payload types is forbidden.

## Unlock slots

Each slot independently wraps the same VRK and contains public metadata plus one
AEAD envelope:

| Field                     | Meaning                                                                      |
| ------------------------- | ---------------------------------------------------------------------------- |
| `slotId`                  | Random opaque identifier, bound into AAD                                     |
| `slotType`                | `portable`, `passphrase`, `recovery`, or `device`                            |
| `slotVersion`             | Schema/parser version                                                        |
| `derivation`              | Exact algorithm ID, version, salt, parameters, output length, and context ID |
| `wrappedVrk`              | Versioned XChaCha20-Poly1305 envelope                                        |
| `keyVersion`              | VRK version wrapped by this slot                                             |
| `state`                   | `pending`, `active`, or `revoked`; unknown states fail closed                |
| `createdAt` / `revokedAt` | Public lifecycle metadata                                                    |
| encrypted label           | Optional label inside a separately encrypted metadata payload                |

### Portable slot

After strict decoding and checksum validation, the raw 32-byte portable key is
the input keying material to HKDF-SHA-256. The per-slot salt and exact info string
above produce a 32-byte KEK. The KEK unwraps only that slot's VRK envelope.
Malformed portable keys are rejected locally before network or decrypt work.

The raw key and KEK are held in mutable byte buffers where the binding permits
and cleared immediately after the unwrap attempt.

### Passphrase slot

Passphrases arrive only through a masked prompt or explicit protected stdin.
They are not trimmed, Unicode-normalized, or accepted as ordinary flags. The
exact input bytes, a fresh 16-byte salt, and Kavrix's serialized Argon2id
parameters derive a 32-byte KEK through the asynchronous Node API.

The floor is m=65536 KiB, t=3, p=4, version 0x13. Calibration may raise memory
and/or passes to a documented latency budget on the device creating the slot,
but it must not silently weaken the floor for speed. A client that cannot safely
allocate the recorded cost fails explicitly rather than substituting weaker
parameters. Parameter and denial-of-service bounds are validated before
allocation.

A user-entered sentence is a passphrase, not a portable key. Changing a
passphrase creates and fully verifies a replacement wrapping of the VRK before
the old slot can be revoked; item ciphertext is untouched.

### Recovery slot

Initialization creates a recovery key independently from the portable key. It
has 32 random bytes and uses a distinct versioned copy format and HKDF info
domain. Only its wrapped VRK envelope and public derivation metadata are
uploaded. The plaintext recovery key is shown once and may be placed in an
encrypted recovery kit; it is never regenerated to the same value.

Replacement creates and verifies a new recovery slot before revocation of the
old one. Losing all active unlock methods is deliberately unrecoverable: there
is no service-side backdoor.

### Device slot

After a normal portable-key enrollment, a device may create an independent
random 32-byte device secret and store it only through the native OS keychain.
Its KEK wraps the same VRK. Missing keychain support means the slot is not
created; plaintext-file fallback is forbidden. Deleting local keychain material
and revoking the device's API token are separate operations.

## Authenticated envelopes

Every non-streaming encrypted object uses a self-describing envelope.
Conceptually:

```text
{
  envelopeVersion,
  algorithm: "xchacha20-poly1305-ietf",
  keyVersion,
  nonce,          // 24 bytes, base64url in JSON/BSON representation
  ciphertext,     // includes/associates the 16-byte authentication tag
  aadVersion,
  payloadType
}
```

Runtime schemas enforce exact known versions, canonical encodings, byte lengths,
and bounded ciphertext sizes before entering the cryptographic library. Unknown
versions and fields that create semantic ambiguity fail closed. A fresh random
24-byte nonce is generated for every encryption under a key. Nonces are stored
with ciphertext and never derived from timestamps, counters without persistent
state, object IDs, or plaintext.

AEAD decryption completes authentication before plaintext is parsed, rendered,
written, or returned. Authentication failure returns no partial content. User-
facing errors do not distinguish wrong key, corrupted envelope, altered AAD, or
near-matching input.

### Attachment streams

Attachment content uses libsodium secretstream rather than treating independent
chunks as interchangeable AEAD records. A random attachment key initializes one
stream and produces a public header. The encrypted attachment metadata binds the
header, chunk size/count, total plaintext size, content hash, and attachment-key
version. The attachment key is wrapped under the owning item's key.

Chunks are processed strictly in ascending index with canonical AAD containing
the vault, item, attachment, stream version, and chunk index. Each non-final
chunk uses the message tag and exactly one terminal chunk uses the final tag.
Missing, duplicated, reordered, appended, or altered chunks; a wrong header;
absence of the final tag; and authenticated size/hash mismatch all fail the
export before the final destination is committed. Readers bound chunk count,
chunk size, and total output before allocating or writing. Secretstream state is
sequential; version 1 does not promise random-access decryption.

Writers copy each caller chunk before advancing its producer and calculate the
manifest count, total size, and SHA-256 from those exact owned bytes. The safe
writer stages canonical header/chunk records, obtains the internally generated
manifest only after the final tag, and atomically commits records plus manifest.
It aborts the staging sink on producer, encryption, record-write, or commit
failure. Callers must not reconstruct a manifest from mutable source buffers.
Readers likewise stage provisional plaintext and commit it only after the final
tag and manifest count, size, header, and plaintext hash have all verified.

## Additional Authenticated Data

AAD binds ciphertext to its immutable context. Version 1 AAD is encoded by one
canonical binary serializer using length-prefixed fields and a fixed field
order; string concatenation, locale-dependent JSON, and caller-selected omission
are forbidden.

The schema includes all applicable fields:

```text
aadVersion
vaultId
groupId
itemId
attachmentId or chunkIndex
slotId
payloadType
schemaVersion
keyVersion
```

Absent values have a single canonical representation. IDs are validated opaque
bytes/ASCII before encoding. Examples of distinct payload types include
`vault-preferences`, `vrk-slot`, `group-key`, `group-payload`, `item-key`,
`item-payload`, `history-event`, `audit-event`, `backup-manifest`,
`attachment-metadata`, and `attachment-chunk`.

Mutable information such as display names, sort order, and timestamps is not
used as identity AAD unless its mutation protocol explicitly re-encrypts the
payload. Immutable identity and interpretation fields are mandatory. Tests must
swap each ID/type/version independently and prove authentication failure.

## Lifecycle and rotation

### Unlock-method change

Adding or changing a portable key, passphrase, recovery key, or device key:

1. Unwraps the current VRK through an already valid slot.
2. Derives a new KEK with fresh public salt/parameters.
3. Wraps the same VRK into a `pending` slot with a fresh nonce.
4. Performs a full authenticated unwrap and constant-time comparison against the
   in-memory VRK.
5. Commits the slot as `active` atomically.
6. Revokes an old slot only after policy checks, including the last-valid-slot
   guard and any selected multi-device grace period.

Credential payloads are not re-encrypted.

### VRK rotation

A new random VRK re-wraps every active group key. The migration is versioned,
checkpointed, and idempotent. The old VRK remains only for the minimum period
needed to verify all new group-key envelopes and commit the new version.
Interrupted work resumes from authenticated checkpoints; it never overwrites the
last usable envelope.

Every checkpoint is authenticated under a domain-separated key derived from the
VRK and binds the vault ID, rotation ID, rotation kind, source/destination key
versions, and an ordered record set. Each record-set entry contains both the
record ID and the SHA-256 digest of its source ciphertext/envelope. Progress can
advance only the next entry, never an arbitrary index. Each advance includes the
canonical replacement digest in an authenticated processed-prefix transcript,
so skipped, duplicated, reordered, or source-changed work fails closed.

The required persistence order for each record is:

1. Create the replacement while retaining the old envelope and old key.
2. Durably persist the replacement and read it back to verify its digest.
3. Advance exactly that record in memory and durably persist the returned
   authenticated checkpoint.
4. Retain old envelopes and keys until the completed checkpoint authenticates
   and is itself durable.

The cryptographic API names the second step as a durably persisted replacement,
but cannot prove filesystem/database durability. Adapters remain responsible for
atomic persistence, read-back verification, and crash recovery in this order.

### Group-key rotation

A new random group key re-wraps each existing item key in that group. Item
payload ciphertext is unchanged. Moving an item between groups requires a
deliberate item-key re-wrap under the destination group key and new AAD-bound
envelopes.

### Item-key rotation

A new random item key re-encrypts that item's payload and history as required.
It does not affect other items. Attachment keys rotate independently; attachment
rewrites must stream and verify every chunk.

`VaultMutationService.rotateItemKeys`, exposed as `creds key rekey`, implements
this for whole groups or an explicit credential selection. The wrapped item key
and the payload it protects live in the same record, so each rotated item is one
self-contained revision-bound mutation: the group key, the vault root key, the
key version, and the associated data of every envelope are unchanged, and only
the wrapped item key and the payload ciphertext are replaced. An interruption
therefore leaves every record readable under whichever key it currently holds,
and re-running the command rotates the remainder.

Two categories are refused rather than rotated, and are reported as skips:

- **Attachment-bearing items.** Attachment keys are wrapped under the item key,
  and republishing them requires restreaming every chunk through
  `beginAttachmentStream`/`writeChunk`/`finalize`, which no single mutation batch
  can carry. Rotating the item key alone would strand the attachment keys.
- **Deleted items.** A tombstone holds no live item key.

Remaining limitations, recorded so they are not mistaken for implemented
behavior:

- **Group-key rotation is not exposed.** `mongo-vault-storage` rejects any
  `wrappedGroupKey` or `wrappedItemKey` change on a group mutation and requires
  `templateVersion` to increase, so the only atomic group-plus-items channel
  cannot carry a rekey.
- **Vault-root-key rotation is not exposed.** Re-wrapping the VRK needs every
  active slot's secret at once, and advancing `currentKeyVersion` would break
  audit-record verification, which binds the recorded key version.
- **Attachment-content rotation is not exposed.** `RotationKind` has no
  `attachment` member; attachment records can only be republished through the
  streaming attachment port.
- **Checkpointed resume is not composed here.** `createRotationCheckpoint`
  requires `toKeyVersion > fromKeyVersion`, which contradicts keeping the key
  version exact. Its validation was deliberately left unchanged; item-key
  rotation is instead idempotent by re-running.

Old keys are not a general history mechanism. Encrypted history retains the
envelopes necessary under an explicit retention design, while obsolete
migration keys are securely discarded after commit. A key-version registry and
rotation state make mixed-version reads explicit. No history write path exists
today, so item-key rotation cannot strand a history envelope; any future change
that begins publishing history records must extend item-key rotation before it
ships.

## Portable key files

An unprotected version 1 file is ASCII and contains:

```text
-----BEGIN CREDVAULT PORTABLE KEY-----
Version: 1
Binding: bound
Vault-ID: <opaque-vault-id>
Key-ID: <opaque-key-slot-id>
Key: cvk1_<canonical-key>
-----END CREDVAULT PORTABLE KEY-----
```

An intentionally unbound version uses an explicit discriminant and reserved
sentinels; the string `unbound` remains a valid opaque bound identifier:

```text
-----BEGIN CREDVAULT PORTABLE KEY-----
Version: 1
Binding: unbound
Vault-ID: -
Key-ID: -
Key: cvk1_<canonical-key>
-----END CREDVAULT PORTABLE KEY-----
```

A passphrase-protected file replaces `Key` with a versioned protection block
containing exact Argon2id parameters, salt, XChaCha20-Poly1305 nonce, AAD
version, and ciphertext. The AAD authenticates the begin/end label, file format
version, vault/key binding, protection algorithm, and serialized KDF parameters.
The passphrase is local-only and follows the passphrase-slot input rules.

```text
-----BEGIN CREDVAULT PORTABLE KEY-----
Version: 1
Binding: bound
Vault-ID: <opaque-vault-id>
Key-ID: <opaque-key-slot-id>
Protection: argon2id+xchacha20-poly1305-ietf
KDF-Version: <version>
KDF-Salt: <canonical-base64url>
KDF-Memory-KiB: <memory>
KDF-Passes: <passes>
KDF-Parallelism: <lanes>
KDF-Output-Length: 32
Nonce: <canonical-base64url>
AAD-Version: 1
Ciphertext: <canonical-base64url>
Authentication-Tag: <canonical-base64url>
-----END CREDVAULT PORTABLE KEY-----
```

For `Binding: unbound`, both ID values are exactly `-`; for `Binding: bound`,
both are validated opaque IDs and `-` is forbidden.

Readers accept exactly one document, bounded in size, with strict header order
and duplicate-header rejection. They reject symlinks, non-regular files, unsafe
ownership, group/world-readable Unix modes, and non-user-only Windows ACLs
unless an explicit safe-warning override applies. Creation is atomic, uses 0600
or a user-only ACL before content is written, does not overwrite by default, and
never silently copies the file into application data.

## Device enrollment and transport

Enrollment authorization is cryptographically independent of encryption:

- Initial vault bootstrap has no invite parent. Before the request, the client
  independently generates and natively protects a canonical random 32-byte API
  session credential. It sends the base64url form only as the HTTPS bearer; the
  enabled bootstrap service atomically claims the SHA-256 hash with the initial
  ciphertext-only vault/device/sync state and returns only opaque IDs.
- An invite is a high-entropy API secret, hashed at rest, short-lived,
  single-use, revocable, and rate-limited.
- Before each exchange, the joining client generates and durably protects a new
  independent high-entropy successor credential. The API receives it only in a
  dedicated redacted header, atomically claims its globally unique hash, and
  never returns or stores the plaintext. Exact retries reuse the same successor
  only before the original authorization expires.
- The joining client downloads public portable-slot parameters and the wrapped
  VRK, then derives and unwraps locally with the user's portable key.
- Neither invite nor device token is accepted as an unlock key. Neither portable
  nor recovery key is accepted by an enrollment/API schema.

The native keychain stores raw session-credential bytes under a distinct
device-scoped locator. Session credentials and device-unlock secrets are both
32-byte values but have separate branded schemas and ports; byte length does not
make them interchangeable. There is no file fallback. JavaScript/native copies
are cleared best effort and cannot be guaranteed zeroized.

TLS is mandatory in production because client-side encryption does not protect
bearer tokens, request metadata, or service integrity. The full flow appears in
[portable-key-and-device-enrollment.md](./portable-key-and-device-enrollment.md).

## Memory, output, and process handling

Key material should use `Uint8Array`/`Buffer` and library secure-memory features
where available, avoid conversion to immutable JavaScript strings, and be
overwritten promptly. Decrypted objects must not live in global state; locking,
signals, cancellation, and fatal paths clear state best effort.

V8, the operating system, swap, crash dumps, terminal software, and copied
buffers prevent a guarantee of complete erasure. The design minimizes exposure
but does not claim perfect memory secrecy.

Secrets enter only through masked prompts, protected key files, explicit stdin,
or an explicitly enabled native keychain. They do not enter normal arguments,
URLs, default environment variables, configuration files, telemetry, debug
logs, or crash messages. `creds run` may place explicitly mapped fields in a
child's environment for that process lifetime; it uses `shell: false`, never
puts values in argv, and releases references after exit.

## Metadata leakage

Encryption does not hide all metadata. The server can observe opaque vault,
device, group, item, and attachment relationships; record and ciphertext sizes;
versions; tombstone state; timestamps; sync sequence; request timing; network
addresses; and traffic volume. Plaintext names, aliases, tags, template field
names, note content, filenames, MIME types, audit details, and secret values must
remain inside encrypted payloads.

Padding, traffic shaping, private information retrieval, transparency logs, and
server-verifiable rollback prevention are outside the initial design. They must
not be implied by the term zero knowledge.

## Test and review requirements

Cryptographic code is test-first and release-blocking. Required evidence
includes official HKDF/Argon2 vectors where applicable; deterministic fixtures
around injected randomness; round trips; independent slots; wrong-key and every
tamper variant; AAD swaps; malformed/oversized input; version rejection;
cross-platform portable-key compatibility; interrupted rotations; last-slot
protection; canary absence; and proof that the API dependency graph cannot
import decryption functions.

Passing tests and dependency audits do not substitute for expert cryptographic
review. Version 1 must receive internal security review before persistence
integration and an independent review before a public production claim.
