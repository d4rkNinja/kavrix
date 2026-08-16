---
'kavrix': minor
---

Expose in-place item-key rotation as `creds key rekey`.

`VaultMutationService.rotateItemKeys` replaces the wrapped item key of every
active credential in one group, or of an explicit `--credential` selection, and
re-encrypts each payload under the fresh key. The wrapped item key and the
payload it protects live in the same record, so each rotated credential is one
revision-bound mutation: the group key, the vault root key, `currentKeyVersion`,
the schema version, and every envelope's associated data stay byte-for-byte
identical, and only the wrapped key and the payload ciphertext change. An
interruption therefore leaves each record readable under whichever key it holds,
and re-running the command rotates only what remains — the rotation is
idempotent by replay rather than by a checkpoint journal.

Two categories are refused rather than rotated, and both are reported with their
reason instead of being folded into a count. Attachment-bearing credentials are
skipped because their attachment keys are wrapped under the item key and can
only be republished by restreaming every chunk through the attachment port, so
rotating the item key alone would strand them. Deleted records are skipped
because a tombstone holds no live item key.

One invocation is one queue transaction, so at most 99 credentials rotate at a
time; a larger, empty, duplicated, or malformed selection is refused before any
mutation is enqueued. Every replacement, item, and group key is zeroized on the
success and the failure path, and the rendered report carries opaque identifiers
and locally decrypted titles only — no key bytes and no field values.

Group-key, vault-root-key, and attachment-content rotation remain uncomposed.
The storage layer rejects any `wrappedGroupKey`/`wrappedItemKey` change on a
group mutation, re-wrapping the vault root key requires every active slot's
secret at once, and advancing the key version would invalidate audit-record
verification. `createRotationCheckpoint` still requires an increasing key
version, which is incompatible with keeping the key version exact; its
validation was deliberately left unchanged.
