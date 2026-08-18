# Cryptography

This page documents the cryptography used by the supported direct-MongoDB vault.
It is a design description, not a claim of formal verification or independent
audit.

## Active security boundary

Kavrix creates, unwraps, and uses secret keys only in the local CLI process.
MongoDB receives a versioned vault document containing public identifiers,
revision metadata, wrapped key slots, recovery-slot metadata, and an encrypted
payload. It does not receive a portable key, recovery key, passphrase, unwrapped
vault root key, or plaintext credential value.

## Primitive suite

- Secret keys are generated from the operating system CSPRNG.
- Vault payloads and wrapped key material use libsodium
  XChaCha20-Poly1305-IETF authenticated encryption with a fresh 24-byte nonce.
- Passphrase-protected portable-key and recovery-kit files derive a key with
  Argon2id using bounded, serialized parameters and fresh salt.
- Domain-separated key derivation and authenticated contexts prevent one key or
  envelope type from being substituted for another.
- Revision anchors use a root-key-derived HMAC-SHA-256 authentication tag.
- Comparisons of authentication material use constant-time byte comparison where
  the runtime API permits it.

Kavrix uses reviewed platform and libsodium primitives. It does not implement a
custom cipher or password hash.

## Key hierarchy

A random vault root key encrypts the current vault payload. The protected
portable key unwraps the root key through the document's active portable slot.
Each recovery kit protects an independent recovery key, and the matching
recovery slot wraps the same root key.

Copying, replicating, or assigning a portable key file creates another protected
file for the same vault binding. Those copies are not independently revocable.
Changing a file passphrase rewraps the local key material; it does not re-encrypt
all credentials.

Recovery use rotates the vault root key and rewrites the current encrypted vault
document. This prevents an old recovery slot from opening the new current
document, but it cannot erase old ciphertext snapshots held elsewhere.

## Authenticated vault document

Local-vault format version 2 binds payload ciphertext to:

- vault identity and payload type;
- schema and key version;
- exact document revision; and
- a digest of security-relevant metadata, including portable and recovery-slot
  state.

Before decryption, Kavrix recomputes the metadata digest and requires it to match
the authenticated envelope. Altering a slot state, revision, binding, or payload
context therefore fails authentication rather than changing behavior silently.
Unknown or malformed versions fail closed.

MongoDB updates use optimistic revision matching. Successful unlocks also read
or advance a restrictive sidecar revision anchor stored beside the active key
file. The anchor is authenticated with a key derived from the vault root key and
contains the highest trusted revision and metadata digest. Lower revisions and
same-revision forks are rejected before plaintext is returned.

If the anchor is missing, normal unlock fails closed. `kavrix doctor health
--accept-current` can initialize it only as an explicit operator decision after
the current database snapshot has been independently verified.

## Protected files

Portable keys, recovery kits, and revision anchors are bounded, strict formats.
File operations reject unsafe paths, links, malformed input, ambiguous content,
and unsafe permissions. Creation is atomic and does not overwrite by default.
Unix modes and Windows ACLs are checked according to the supported platform
implementation.

Passphrases are read through masked prompts or explicit framed stdin. Kavrix does
not accept plaintext unlock material in ordinary positional arguments, URLs, or
settings files.

## Limits

Authenticated encryption does not hide vault IDs, revisions, timestamps,
ciphertext sizes, or database access patterns. It also cannot prevent MongoDB
deletion or withholding.

Kavrix cannot protect an unlocked host against administrator access, same-user
malware, keylogging, terminal capture, clipboard capture, process inspection,
swap, or crash dumps. Secret byte buffers are cleared best effort, but the
JavaScript runtime cannot guarantee complete memory erasure.

A passing test suite and dependency audit do not replace independent
cryptographic review.
