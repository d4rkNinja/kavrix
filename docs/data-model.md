# Data model

Kavrix stores one versioned encrypted document per vault in a protected local
file or MongoDB. The
canonical runtime contract lives in `packages/schemas/src/local-vault.ts`; this
page is a user-facing summary.

## Datastore-visible document

A local-vault version 2 document includes:

- the format discriminator and vault ID;
- schema and current key versions;
- the active portable-key slot envelope;
- bounded recovery-slot envelopes and their state;
- document revision and timestamps;
- authenticated payload-envelope metadata, nonce, and ciphertext.

MongoDB can observe these fields, document size, update timing, and query
patterns. A process able to read the local file can observe the same fields and
file-update timing. They are operational metadata, not secret values.

## Encrypted payload

The authenticated payload contains the credential records. Each record has a
normalized name, value, and record timestamps. Names and values are encrypted
together; `list`, `search`, and `view` decrypt locally and then deliberately
render names without values.

Kavrix does not create plaintext credential collections, indexes, search fields,
settings files, or API records. MongoDB cannot search credential names because
it sees only the encrypted payload.

## Key slots

The document's portable slot wraps the vault root key for the protected key file.
Recovery slots wrap the root key for separately protected recovery kits. Slot
identity, type, binding, key version, state, and revocation metadata are included
in authenticated document metadata. The number of recovery slots is bounded by
the runtime schema.

A copied portable key file retains the same vault and slot binding. It is another
copy of the same authorization, not a separately revocable database identity.

## Revisions and concurrency

Every write increments the vault revision. Both datastore adapters replace a
document only when the stored revision matches the caller's expected revision;
concurrent writers fail with a conflict rather than silently overwriting each
other.

The encrypted payload authenticates the exact revision and metadata digest. A
root-key-authenticated local anchor records the highest trusted revision and
digest for the active key-file path. This detects an older snapshot or a
same-revision fork, provided the trusted anchor remains available.

## Validation

Runtime schemas reject unknown versions, extra ambiguous fields, invalid IDs,
invalid encodings, oversized values, malformed envelopes, and inconsistent
associated data before plaintext is used. Cryptographic authentication is
completed before the payload is parsed or rendered.

Only local-vault version 2 is accepted by the current CLI. Older formats are not
silently migrated because doing so would bypass the current metadata-binding and
rollback rules.
