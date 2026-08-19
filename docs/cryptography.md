# Cryptography

This page documents the cryptography used by the supported local-file and
direct-MongoDB database container and the legacy version 2 vault format.
It is a design description, not a claim of formal verification or independent
audit.

## Active security boundary

Kavrix creates, unwraps, and uses secret keys only in the local CLI process.
MongoDB receives a versioned database document and per-vault documents containing
opaque identifiers, revision metadata, wrapped key slots, recovery-slot metadata,
and encrypted envelopes. It does not receive a portable key, recovery key,
passphrase, DRK, VRK, private label, or plaintext credential value.

## Primitive suite

- Secret keys are generated from the operating system CSPRNG.
- Vault payloads and wrapped key material use libsodium
  XChaCha20-Poly1305-IETF authenticated encryption with a fresh 24-byte nonce.
- Passphrase-protected portable-key and recovery-kit files derive a key with
  Argon2id using bounded, serialized parameters and fresh salt.
- HKDF-SHA-256 with versioned domains derives independent catalog, wrapping, and
  anchor keys. Authenticated contexts prevent substitution across database,
  vault, entity, purpose, version, and revision.
- Revision anchors use a root-key-derived HMAC-SHA-256 authentication tag.
- Comparisons of authentication material use constant-time byte comparison where
  the runtime API permits it.

Kavrix uses reviewed platform and libsodium primitives. It does not implement a
custom cipher or password hash.

## Database key hierarchy

Database initialization generates a random 256-bit database root key (DRK). A
random portable database key wraps the DRK and is stored in the protected owner
key file. Database recovery kits contain independently protected recovery
material whose slots wrap the same DRK.

Every vault receives a separate random vault root key (VRK). A DRK-derived key
wraps each VRK using exact database/vault associated data. Compromise of a VRK
does not derive the DRK or another VRK. Database recovery preserves the DRK and
therefore owner access to every independently wrapped vault; it does not rotate
all VRKs or erase historical ciphertext.

## Legacy version 2 key hierarchy

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

Database-container envelopes bind the database ID, vault ID when applicable,
entity/purpose, schema/cryptographic/key versions, database or vault revision,
and metadata digest. The private catalog binds its ordered vault mapping to the
database revision. Wrapped VRKs cannot move between databases or vaults.

The section below describes the retained version 2 single-vault compatibility
format.

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

Database-container updates use exact expected revisions and MongoDB transactions
for multi-document publication. Successful unlocks reconcile a restrictive
sidecar authenticated by a DRK-derived key. It contains the database/catalog head
and authenticated vault-head set; rollback, same-revision forks, and inconsistent
vault presence fail before plaintext is returned. Legacy version 2 anchors retain
their VRK-authenticated revision/digest contract.

If an anchor is missing, normal unlock fails closed. Legacy `kavrix doctor health
--accept-current` applies only to a version 2 single-vault anchor; it is not a
database-container bypass.

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
