# Database Container Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the independently releasable database foundation that binds one protected database-owner key to one database, stores multiple encrypted vaults in MongoDB or one protected local container, supports non-secret datastore profiles and switching, and explicitly migrates the current version 2 single-vault format.

**Architecture:** Introduce a canonical database document containing a DRK-wrapped private catalog and independent database-vault documents whose VRKs are wrapped by the DRK. Storage exposes one database-scoped compare-and-swap port; MongoDB uses transactions for catalog-plus-vault mutations and the local adapter atomically rewrites one bounded container. Existing flat credential payloads remain unchanged in this phase, so current credential commands can operate after selecting a vault while hierarchy and user sharing arrive in later plans.

**Tech Stack:** Strict ESM TypeScript, Zod 4 runtime schemas, libsodium XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, MongoDB 7 transactions, Node protected filesystem APIs, Commander 15, Vitest 4, pnpm workspaces.

**Spec:** `docs/superpowers/specs/2026-08-19-database-multivault-sharing-design.md`

## Global Constraints

- Never persist, transmit, log, or place in process arguments plaintext portable keys, passphrases, recovery keys, DRKs, VRKs, MongoDB credentials, or decrypted credential data.
- MongoDB may receive only the limited routing metadata and authenticated ciphertext approved in the specification.
- Local mode stores multiple vaults in one database file and grants full access to anyone holding that file, its matching database-owner key file, and the passphrase.
- User identities, grants, roles, and recipient discovery are not implemented in this foundation; local mode must reject those future commands explicitly when they arrive.
- Use XChaCha20-Poly1305-IETF, Argon2id, and HKDF-SHA-256 through existing reviewed libraries; do not invent a primitive.
- Preserve the current version 2 local-vault format and stable credential commands until an explicit copy-first migration succeeds.
- Keep Node support at `>=24.12.0 <25 || >=25.1.0`.
- Keep secrets in masked prompts, protected files, or explicit bounded stdin frames only.
- Use `spawn` or `execFile` with argument arrays and `shell: false` for every child process.
- Every task is test-first, leaves the branch releasable, and ends in a focused commit.

## File structure

- `packages/schemas/src/database-container.ts`: canonical database AAD, encrypted envelope, catalog, database, vault, and local-container contracts.
- `packages/schemas/src/identifiers.ts`: branded database and profile identifiers.
- `packages/crypto/src/database-crypto.ts`: DRK generation, database-domain AEAD, catalog encryption, DRK slot wrapping, and VRK wrapping.
- `packages/key-files/src/database-key-files.ts`: protected database-owner portable-key file bound to one database ID.
- `packages/key-files/src/database-revision-anchor.ts`: DRK-authenticated database/catalog head anchor.
- `packages/storage/src/encrypted-database-store.ts`: database-scoped persistence port and errors.
- `packages/storage/src/mongo-encrypted-database.ts`: transactional MongoDB implementation.
- `packages/storage/src/file-encrypted-database.ts`: atomic bounded local-container implementation.
- `apps/cli/src/datastore-profiles.ts`: non-secret protected profile registry and current-profile selection.
- `apps/cli/src/database-session.ts`: unlock, binding, catalog, anchor, and store orchestration.
- `apps/cli/src/database-commands.ts`: database/profile command composition and handlers.
- `apps/cli/src/database-migration.ts`: explicit legacy version 2 copy-first migration.
- `apps/cli/src/local-vault-cli.ts`: compatibility wiring only; move database-specific composition into the focused modules above.
- `acceptance/pre-ci/database-container/run.js`: packed multi-vault, switching, migration, and cleanup acceptance.

---

### Task 1: Canonical database-container schemas

**Files:**

- Modify: `packages/schemas/src/identifiers.ts`
- Create: `packages/schemas/src/database-container.ts`
- Modify: `packages/schemas/src/index.ts`
- Create: `packages/schemas/test/database-container.test.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: existing `aeadEnvelopeSchema`, `keyVersionSchema`, `localVaultPayloadSchema`, timestamp and revision primitives.
- Produces: `databaseIdSchema`, `profileIdSchema`, `databaseRevisionSchema`, `databaseAssociatedDataSchema`, `databaseAeadEnvelopeSchema`, `databaseCatalogPayloadSchema`, `databaseRecoverySlotSchema`, `encryptedDatabaseDocumentSchema`, `databaseVaultDocumentSchema`, `fileDatabaseContainerSchema`, and inferred branded types.

- [ ] **Step 1: Write identifier and strict-schema failure tests**

Add tests that parse a canonical fixture and reject every mutation independently:

```ts
const databaseId = databaseIdSchema.parse('db_01JTESTDATABASE');
const vaultId = vaultIdSchema.parse('vault_01JPROJECTA');

expect(encryptedDatabaseDocumentSchema.parse(databaseFixture(databaseId))).toEqual(
  databaseFixture(databaseId),
);
expect(() =>
  encryptedDatabaseDocumentSchema.parse({
    ...databaseFixture(databaseId),
    plaintextLabel: 'production',
  }),
).toThrow();
expect(() =>
  databaseVaultDocumentSchema.parse({
    ...vaultFixture(databaseId, vaultId),
    databaseId: databaseIdSchema.parse('db_01JOTHERDATABASE'),
  }),
).toThrow();
```

Cover unknown keys, unsupported versions, duplicate catalog vault IDs, catalog/document revision disagreement, wrong database/vault AAD, invalid ciphertext bounds, noncanonical base64url, more than 1,000 vaults, and a local container whose map key differs from its vault ID.

- [ ] **Step 2: Run the schema test and confirm it fails**

Run: `pnpm exec vitest run packages/schemas/test/database-container.test.ts`

Expected: failure because the new exports do not exist.

- [ ] **Step 3: Add branded identifiers and database schemas**

Add:

```ts
export const databaseIdSchema = opaqueId.brand<'DatabaseId'>();
export const profileIdSchema = opaqueId.brand<'ProfileId'>();
export type DatabaseId = z.infer<typeof databaseIdSchema>;
export type ProfileId = z.infer<typeof profileIdSchema>;
```

Define strict version 1 database contracts with these exact top-level shapes:

```ts
export const databaseRevisionSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER)
  .brand<'DatabaseRevision'>();

const opaqueDatabaseEntityIdSchema = z.union([
  databaseIdSchema,
  vaultIdSchema,
  keySlotIdSchema,
]);

export const databaseAssociatedDataSchema = z
  .object({
    version: z.literal(1),
    databaseId: databaseIdSchema,
    entityType: z.enum([
      'database-catalog',
      'wrapped-database-root',
      'wrapped-vault-root',
    ]),
    entityId: opaqueDatabaseEntityIdSchema,
    purpose: z.enum(['catalog', 'database-root', 'vault-root']),
    schemaVersion: supportedSchemaVersionSchema,
    keyVersion: keyVersionSchema,
    revision: databaseRevisionSchema,
    vaultId: vaultIdSchema.optional(),
    metadataDigest: sha256DigestSchema,
  })
  .strict();

export const databaseCatalogPayloadSchema = z
  .object({
    label: z.string().trim().min(1).max(256),
    vaults: z
      .array(
        z
          .object({
            id: vaultIdSchema,
            label: z.string().trim().min(1).max(256),
            createdAt: timestampSchema,
          })
          .strict(),
      )
      .max(1_000),
  })
  .strict();
```

`databaseAeadEnvelopeSchema` uses the existing algorithm/nonce/ciphertext/tag
fields with `databaseAssociatedDataSchema`. `databasePortableKeySlotSchema` and
`databaseRecoverySlotSchema` are strict database-domain wrappers and do not
reuse the vault-only `keySlotSchema`. `encryptedDatabaseDocumentSchema`
contains the format/version, database ID, schema/cryptographic/key versions,
one active database portable-key slot, at most 32 active or revoked recovery
slots, revision, encrypted catalog, timestamps, and catalog metadata digest.
`databaseVaultDocumentSchema` contains database ID, vault ID, wrapped VRK,
legacy-compatible encrypted flat payload, key/document revisions, timestamps,
and metadata digest. `fileDatabaseContainerSchema` contains exactly one database
document and a record of up to 1,000 vault documents.

- [ ] **Step 4: Export and register the schema tests**

Export `database-container.ts` from `packages/schemas/src/index.ts` and include
`packages/schemas/test/database-container.test.ts` in `vitest.config.ts`.

- [ ] **Step 5: Run schema verification**

Run:

```sh
pnpm exec vitest run packages/schemas/test/database-container.test.ts
pnpm --filter @kavrix/schemas typecheck
pnpm --filter @kavrix/schemas build
```

Expected: all commands pass.

- [ ] **Step 6: Commit the schema contract**

```sh
git add packages/schemas/src packages/schemas/test/database-container.test.ts vitest.config.ts
git commit -m "feat(schemas): define encrypted database containers"
```

### Task 2: Database-domain cryptography

**Files:**

- Create: `packages/crypto/src/database-crypto.ts`
- Modify: `packages/crypto/src/keys.ts`
- Modify: `packages/crypto/src/index.ts`
- Create: `packages/crypto/test/database-crypto.test.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: Task 1 database schemas and existing byte, base64url, Argon2id, HKDF, canonical JSON, and sodium helpers.
- Produces: `DatabaseRootKey`, `generateDatabaseRootKey()`, `canonicalDatabaseAssociatedData()`, `encryptDatabaseAead()`, `decryptDatabaseAead()`, `createDatabaseKeySlot()`, `unlockDatabaseKeySlot()`, `createDatabaseRecoverySlot()`, `unlockDatabaseRecoverySlot()`, `encryptDatabaseCatalog()`, `decryptDatabaseCatalog()`, `wrapVaultRootForDatabase()`, and `unwrapVaultRootForDatabase()`.

- [ ] **Step 1: Write cryptographic misuse and tamper tests**

Use deterministic 32-byte fixtures only inside tests. Assert round trips and
reject tampered database ID, vault ID, purpose, entity ID, revision, metadata
digest, nonce, ciphertext, tag, and key version. Add a plaintext canary and
assert it is absent from serialized envelopes.

```ts
await expect(
  decryptDatabaseAead(envelope, databaseRootKey, {
    ...context,
    databaseId: databaseIdSchema.parse('db_01JWRONG'),
  }),
).rejects.toBeInstanceOf(AuthenticationError);

const unwrapped = await unwrapVaultRootForDatabase(
  wrappedVaultRoot,
  databaseRootKey,
  vaultContext,
);
expect(unwrapped).toEqual(vaultRootKey);
zeroize(unwrapped);
```

- [ ] **Step 2: Run the crypto test and confirm it fails**

Run: `pnpm exec vitest run packages/crypto/test/database-crypto.test.ts`

Expected: failure because `database-crypto.ts` does not exist.

- [ ] **Step 3: Add the branded DRK and canonical AAD codec**

Add `DatabaseRootKey = SecretKey<'database-root'>` and:

```ts
export function generateDatabaseRootKey(): DatabaseRootKey {
  return randomSecret<'database-root'>();
}
```

Use a separate domain `kavrix/database-aad/v1` and length-prefix every AAD field.
Do not modify the byte encoding of existing vault AAD. Database AAD encodes the
optional vault ID with an explicit presence byte.

- [ ] **Step 4: Implement the narrow database cryptographic API**

`encryptDatabaseAead` and `decryptDatabaseAead` must call libsodium detached
XChaCha20-Poly1305 directly, require 32-byte keys, enforce existing ciphertext
bounds, compare stored and expected canonical AAD in constant time, map all
decrypt failures to `AuthenticationError`, and zero nonce/ciphertext/tag/AAD
buffers in `finally`.

`createDatabaseKeySlot` derives a KEK from the portable key with a new
`kavrix/database-root-wrap/v1` HKDF domain. `wrapVaultRootForDatabase` uses the
DRK and requires `entityType: 'wrapped-vault-root'` with the exact vault ID.
`createDatabaseRecoverySlot` uses a separately generated recovery key and the
domain `kavrix/database-recovery-wrap/v1`; it cannot accept a vault recovery
slot or unlock a vault-only document.

- [ ] **Step 5: Run focused crypto verification**

Run:

```sh
pnpm exec vitest run packages/crypto/test/database-crypto.test.ts
pnpm --filter @kavrix/crypto typecheck
pnpm --filter @kavrix/crypto build
```

Expected: all commands pass and no existing known-answer vector changes.

- [ ] **Step 6: Commit database cryptography**

```sh
git add packages/crypto/src packages/crypto/test/database-crypto.test.ts vitest.config.ts
git commit -m "feat(crypto): add database key hierarchy"
```

### Task 3: Protected database key files and database anchors

**Files:**

- Create: `packages/key-files/src/database-key-files.ts`
- Create: `packages/key-files/src/database-recovery-kit-files.ts`
- Create: `packages/key-files/src/database-revision-anchor.ts`
- Modify: `packages/key-files/src/index.ts`
- Create: `packages/key-files/test/database-key-files.test.ts`
- Create: `packages/key-files/test/database-recovery-kit-files.test.ts`
- Create: `packages/key-files/test/database-revision-anchor.test.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: Task 1 IDs, Task 2 portable database key and DRK types, existing protected-file and Windows ACL primitives.
- Produces: `DatabaseKeyBinding`, `writeDatabaseKeyFile()`, `readDatabaseKeyFile()`, `DatabaseRecoveryBinding`, `writeDatabaseRecoveryKitFile()`, `readDatabaseRecoveryKitFile()`, `databaseRevisionAnchorSchema`, `writeDatabaseRevisionAnchor()`, `readDatabaseRevisionAnchor()`, and `databaseRevisionAnchorPath()`.

- [ ] **Step 1: Write protected-file failure tests**

Cover passphrase-protected round trip, wrong passphrase, wrong database ID,
wrong key-slot ID, version mutation, trailing data, oversized input, unsafe
permissions, symlink, hardlink, replacement race, initially existing target,
Windows ACL calls, and plaintext-canary absence.

```ts
await writeDatabaseKeyFile(path, portableKey, binding, {
  mode: 'create',
  protection: { kind: 'passphrase', passphrase },
});
const parsed = await readDatabaseKeyFile(path, passphrase, binding);
expect(parsed.binding).toEqual(binding);
expect(parsed.portableKey).toEqual(portableKey);
zeroize(parsed.portableKey);
```

Run the same binding, passphrase, filesystem, and plaintext-canary cases for a
database recovery kit. Assert that a database recovery kit is rejected by the
legacy vault-recovery reader and a legacy recovery kit is rejected by the
database reader.

Anchor tests must reject another database ID, lower revision, same-revision
digest fork, wrong DRK, malformed tag, and unsafe filesystem state.

- [ ] **Step 2: Confirm both new tests fail**

Run:

```sh
pnpm exec vitest run packages/key-files/test/database-key-files.test.ts packages/key-files/test/database-recovery-kit-files.test.ts packages/key-files/test/database-revision-anchor.test.ts
```

Expected: failure because the exports are missing.

- [ ] **Step 3: Implement the strict database-key format**

Use a new header and do not overload the existing vault-bound portable-key
format:

```text
-----BEGIN KAVRIX DATABASE KEY-----
Version: 1
Database-ID: <opaque-id>
Key-ID: <opaque-id>
Protection: argon2id+xchacha20-poly1305
Derivation: <canonical-base64url-json>
Nonce: <canonical-base64url>
Ciphertext: <canonical-base64url>
Tag: <canonical-base64url>
-----END KAVRIX DATABASE KEY-----
```

Authenticate the version and binding as AAD. Reuse `readSecureFile`,
`writeSecureFile`, strict destination validation, and byte zeroization.

- [ ] **Step 4: Implement the protected database recovery kit**

Implement the recovery kit first as a strict JSON envelope with format
`kavrix-database-recovery-kit`, version 1, database ID, recovery-slot ID,
Argon2id derivation, nonce, ciphertext, and authentication tag. Bind every
field as AAD and reuse protected-file operations.

- [ ] **Step 5: Implement the DRK-authenticated anchor**

Persist a strict JSON envelope containing format, version, database ID,
database revision, catalog digest, and an HMAC-SHA-256 tag under an
HKDF-SHA-256 DRK-derived anchor key with domain
`kavrix/database-revision-anchor/v1`.

- [ ] **Step 6: Run key-file verification**

Run:

```sh
pnpm exec vitest run packages/key-files/test/database-key-files.test.ts packages/key-files/test/database-recovery-kit-files.test.ts packages/key-files/test/database-revision-anchor.test.ts
pnpm --filter @kavrix/key-files typecheck
pnpm --filter @kavrix/key-files build
```

Expected: all commands pass.

- [ ] **Step 7: Commit protected database files**

```sh
git add packages/key-files/src packages/key-files/test vitest.config.ts
git commit -m "feat(key-files): protect database owner keys"
```

### Task 4: Database-scoped persistence port

**Files:**

- Create: `packages/storage/src/encrypted-database-store.ts`
- Modify: `packages/storage/src/index.ts`
- Create: `packages/storage/test/encrypted-database-store-contract.test.ts`

**Interfaces:**

- Consumes: Task 1 database and vault documents.
- Produces: `EncryptedDatabaseStore`, `EncryptedDatabaseStoreError`, and a reusable adapter contract test factory.

- [ ] **Step 1: Write a compile-time and behavioral fake-adapter contract**

Define the exact port:

```ts
export interface EncryptedDatabaseStore {
  ping(): Promise<void>;
  getDatabase(databaseId: DatabaseId): Promise<EncryptedDatabaseDocument | null>;
  createDatabase(document: EncryptedDatabaseDocument): Promise<void>;
  updateDatabase(
    document: EncryptedDatabaseDocument,
    expectedRevision: DatabaseRevision,
  ): Promise<void>;
  listVaults(databaseId: DatabaseId): Promise<readonly DatabaseVaultDocument[]>;
  getVault(
    databaseId: DatabaseId,
    vaultId: VaultId,
  ): Promise<DatabaseVaultDocument | null>;
  createVault(
    input: Readonly<{
      database: EncryptedDatabaseDocument;
      expectedDatabaseRevision: DatabaseRevision;
      vault: DatabaseVaultDocument;
    }>,
  ): Promise<void>;
  updateVault(
    input: Readonly<{
      vault: DatabaseVaultDocument;
      expectedVaultRevision: VaultRevision;
    }>,
  ): Promise<void>;
  deleteVault(
    input: Readonly<{
      database: EncryptedDatabaseDocument;
      expectedDatabaseRevision: DatabaseRevision;
      vaultId: VaultId;
      expectedVaultRevision: VaultRevision;
    }>,
  ): Promise<void>;
  close(): Promise<void>;
}
```

Contract tests require exact revision increments, database/vault binding,
sorted listing, duplicate rejection, stale database conflict, stale vault
conflict, missing record conflict, closed-state failure, and idempotent close.

- [ ] **Step 2: Run the contract test and confirm it fails**

Run: `pnpm exec vitest run packages/storage/test/encrypted-database-store-contract.test.ts`

Expected: failure because the port is missing.

- [ ] **Step 3: Add the port, mutation inputs, and generic errors**

Use error codes `busy`, `closed`, `conflict`, `connection`, `exists`, `invalid`,
`operation`, and `unsupported`. Do not include IDs, paths, Mongo errors, or
document values in public messages.

- [ ] **Step 4: Make the in-memory contract fixture pass**

The fixture validates the contract test itself without exporting a production
in-memory adapter. It must clone parsed documents rather than return shared
mutable references.

- [ ] **Step 5: Run storage type checking and the contract test**

Run:

```sh
pnpm exec vitest run packages/storage/test/encrypted-database-store-contract.test.ts
pnpm --filter @kavrix/storage typecheck
```

Expected: both commands pass.

- [ ] **Step 6: Commit the persistence boundary**

```sh
git add packages/storage/src packages/storage/test/encrypted-database-store-contract.test.ts
git commit -m "feat(storage): define encrypted database store"
```

### Task 5: Transactional MongoDB multi-vault adapter

**Files:**

- Create: `packages/storage/src/mongo-encrypted-database.ts`
- Modify: `packages/storage/src/index.ts`
- Create: `packages/storage/test/mongo-encrypted-database.test.ts`
- Create: `packages/storage/test/mongo-encrypted-database.integration.test.ts`
- Modify: `packages/storage/vitest.config.ts`

**Interfaces:**

- Consumes: Task 4 `EncryptedDatabaseStore` and existing hardened Mongo URI policy.
- Produces: `MongoEncryptedDatabaseStore.connect(uri, databaseName, options)` implementing the complete port.

- [ ] **Step 1: Write mocked command-shape and error-mapping tests**

Assert validated collection names, `_id` composition, projections, exact CAS
filters, transaction use for catalog-plus-vault mutation, transaction abort on
either failed comparison, duplicate mapping, generic errors, bounded timeouts,
TLS rejection, and client close after connection failure.

The two collections are exactly:

```ts
type MongoEncryptedDatabaseStoreOptions = Readonly<{
  databaseCollectionName?: string;
  vaultCollectionName?: string;
}>;

const DEFAULT_DATABASE_COLLECTION = 'kavrix_databases';
const DEFAULT_VAULT_COLLECTION = 'kavrix_vaults';
```

- [ ] **Step 2: Confirm the focused Mongo tests fail**

Run: `pnpm exec vitest run packages/storage/test/mongo-encrypted-database.test.ts`

Expected: failure because the adapter does not exist.

- [ ] **Step 3: Implement strict parsing and read operations**

Store database documents at `_id: databaseId` and vault documents at
`_id: databaseId + ':' + vaultId`, while persisting canonical `databaseId` and
`id` fields. Strip only Mongo `_id` before Zod parsing. List with a projection
bounded to the selected database ID and sort by opaque vault ID.

- [ ] **Step 4: Implement transactional mutations**

Use `client.withSession()` and `session.withTransaction()` for create/delete
operations that change both the encrypted catalog and a vault. Within the
transaction, update the database document with an exact prior revision filter,
then insert or delete the vault with exact database and vault revision filters.
Ordinary vault payload updates replace only that vault with an exact prior
revision filter, so independent vaults do not contend on the catalog revision.
Throw a conflict to abort when any matched/deleted count differs from one. Use
majority write concern and snapshot read concern; never retry an ambiguous
application error outside the driver transaction callback.

- [ ] **Step 5: Run focused mocked verification**

Run:

```sh
pnpm exec vitest run packages/storage/test/mongo-encrypted-database.test.ts packages/storage/test/mongo-local-vault-uri.test.ts
pnpm --filter @kavrix/storage typecheck
```

Expected: all commands pass.

- [ ] **Step 6: Add disposable replica-set integration coverage**

Gate the integration test on `KAVRIX_MONGODB_URI`. Create a random database
name, exercise two vaults and every conflict case through the real adapter, scan
every stored BSON document for a runtime-random plaintext canary, and drop only
that validated random database in `afterAll`.

- [ ] **Step 7: Commit the MongoDB adapter**

```sh
git add packages/storage/src packages/storage/test packages/storage/vitest.config.ts
git commit -m "feat(storage): add transactional multi-vault MongoDB"
```

### Task 6: Atomic local multi-vault database adapter

**Files:**

- Create: `packages/storage/src/file-encrypted-database.ts`
- Modify: `packages/storage/src/index.ts`
- Create: `packages/storage/test/file-encrypted-database.test.ts`
- Modify: `packages/storage/vitest.config.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: Task 1 `fileDatabaseContainerSchema` and Task 4 port.
- Produces: `FileEncryptedDatabaseStore.open(path)` and `FileEncryptedDatabaseStore.validatePath(path)`.

- [ ] **Step 1: Write the complete file-adapter contract tests**

Reuse Task 4 contract assertions and add two-vault canonical serialization,
32 MiB database bound, per-vault count bounds, process-lifetime lock,
create/replace atomicity, directory synchronization, restrictive temp/final
files, Windows ACL set-and-verify calls, symlink/hardlink/path-replacement
rejection, malformed and noncanonical JSON, truncation, cleanup after failure,
and plaintext-canary absence.

- [ ] **Step 2: Confirm the file adapter test fails**

Run: `pnpm exec vitest run packages/storage/test/file-encrypted-database.test.ts`

Expected: failure because the adapter is missing.

- [ ] **Step 3: Implement safe target resolution and locking**

Extract the already reviewed path, identity, ACL, temporary publication, and
directory-sync primitives from `file-local-vault.ts` into focused internal
helpers only when both adapters can share them without changing legacy output.
Open uses one exclusive sibling `.lock`, validates an existing canonical
container, and starts with no persisted file when the database is absent.

- [ ] **Step 4: Implement atomic container mutations**

For every mutation, parse and clone the complete container, enforce exact
database/vault revisions, serialize `JSON.stringify(container) + '\n'`, write a
restrictive same-directory temporary file, sync it, compare target identity,
rename atomically, verify ACL/mode and canonical contents, then sync the
directory. A failed mutation leaves the prior target unchanged.

- [ ] **Step 5: Run file and legacy adapter regressions**

Run:

```sh
pnpm exec vitest run packages/storage/test/file-encrypted-database.test.ts packages/storage/test/file-local-vault.test.ts
pnpm --filter @kavrix/storage typecheck
pnpm --filter @kavrix/storage build
```

Expected: all commands pass.

- [ ] **Step 6: Commit the file database adapter**

```sh
git add packages/storage/src packages/storage/test packages/storage/vitest.config.ts vitest.config.ts
git commit -m "feat(storage): add encrypted multi-vault files"
```

### Task 7: Non-secret datastore profiles and switching

**Files:**

- Create: `apps/cli/src/datastore-profiles.ts`
- Create: `apps/cli/test/datastore-profiles.test.ts`
- Modify: `apps/cli/src/local-vault-cli.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: Task 1 `DatabaseId` and `ProfileId`, key-files protected filesystem primitives.
- Produces: `DatastoreProfile`, `DatastoreProfileRegistry`, `resolveProfilePath()`, and Commander handlers for `db profile add|list|use|status|remove`.

- [ ] **Step 1: Write profile safety and switching tests**

Use an injected config directory. Assert canonical add/list/use/status/remove,
duplicate aliases, missing current profile, unsafe permissions, link rejection,
atomic replacement, Windows ACL behavior, control characters, bounded counts,
and no URI username/password/token fields.

```ts
const registry = await DatastoreProfileRegistry.open({ configDirectory });
await registry.add({
  id: profileIdSchema.parse('work'),
  datastore: 'mongodb',
  database: 'credentials',
  databaseCollection: 'kavrix_databases',
  vaultCollection: 'kavrix_vaults',
  keyFile: '/protected/work.kavrix-db-key',
});
await registry.use(profileIdSchema.parse('work'));
expect((await registry.current())?.id).toBe('work');
```

- [ ] **Step 2: Confirm the profile test fails**

Run: `pnpm exec vitest run apps/cli/test/datastore-profiles.test.ts`

Expected: failure because the registry does not exist.

- [ ] **Step 3: Implement the strict profile registry**

The JSON format contains version, current profile ID, and at most 64 profiles.
Mongo profiles contain database/collection routing and key path but no URI.
File profiles contain data-file and key paths. After initialization both contain
the expected opaque database ID. Reject keys named `uri`, `password`, `token`,
`secret`, or `credential` at every nesting level.

- [ ] **Step 4: Add profile command composition**

Profile output is sanitized and never displays Mongo credentials. `use` changes
only the selected profile. Existing explicit datastore flags continue to work
and override profile routing without bypassing database-ID binding.

- [ ] **Step 5: Run CLI profile verification**

Run:

```sh
pnpm exec vitest run apps/cli/test/datastore-profiles.test.ts apps/cli/test/local-vault-cli-view.test.ts
pnpm --filter kavrix typecheck
```

Expected: all commands pass and existing help remains stable apart from the new
`db profile` subtree.

- [ ] **Step 6: Commit datastore profiles**

```sh
git add apps/cli/src apps/cli/test/datastore-profiles.test.ts vitest.config.ts
git commit -m "feat(cli): add safe datastore profiles"
```

### Task 8: Database session and owner commands

**Files:**

- Create: `apps/cli/src/database-session.ts`
- Create: `apps/cli/src/database-commands.ts`
- Create: `apps/cli/test/database-session.test.ts`
- Create: `apps/cli/test/database-commands.test.ts`
- Modify: `apps/cli/src/local-vault-cli.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: Tasks 1–7 schemas, crypto, key files, anchors, stores, profiles, and existing secret input.
- Produces: `DatabaseSession.open()`, `DatabaseSession.createVault()`, `DatabaseSession.listVaults()`, `DatabaseSession.getVault()`, `DatabaseSession.updateVault()`, `DatabaseSession.deleteVault()`, plus `db init|status`, `db recovery create|verify|status|revoke|use`, and multi-vault `vault create|list|status|rename` handlers.

- [ ] **Step 1: Write session tests with injected ports**

Test initialization rollback, key-file/database-ID mismatch before catalog
decrypt, wrong passphrase, catalog authentication failure, missing/stale/forked
anchor, two-vault creation, duplicate encrypted label detection after local
decrypt, independent vault update, CAS conflicts, key zeroization, close failure,
and generic error mapping.
Also cover database recovery creation, verification, revocation, last-valid-slot
protection, DRK recovery, destination database-key replacement, and anchor
verification after recovery.

- [ ] **Step 2: Confirm session tests fail**

Run: `pnpm exec vitest run apps/cli/test/database-session.test.ts`

Expected: failure because the session does not exist.

- [ ] **Step 3: Implement initialization and open sequencing**

Initialization validates key and anchor destinations before reading secrets,
generates the portable database key and DRK, creates the database slot and
encrypted empty catalog, writes the protected key, publishes the database,
writes and verifies the anchor, then reports sanitized IDs and paths. Rollback
removes every owned artifact; if datastore rollback fails, retain the key needed
for recovery and aggregate errors.

Open resolves the profile/store, reads secrets once, verifies the key-file
database binding, unlocks the DRK, authenticates the catalog, compares the
database anchor, and only then exposes vault operations.

- [ ] **Step 4: Implement vault lifecycle with fresh VRKs**

`createVault(label)` generates an opaque random vault ID and VRK, wraps the VRK
under the DRK, creates an empty legacy-compatible encrypted payload, updates the
encrypted catalog, and calls one store transaction. Rename changes only the
encrypted catalog. Delete removes the vault and catalog entry atomically after
the existing guarded destruction policy is adapted in a later focused task;
this task exposes no unguarded delete command.

Database recovery commands operate on DRK recovery slots and
`kavrix-database-recovery-kit` files only. Recovery use creates a fresh
database-owner portable key file, rewraps the DRK without changing vault
ciphertext, verifies the destination key and anchor, and never overwrites the
only working owner key without an explicit safe destination.

- [ ] **Step 5: Write and implement command tests**

Test masked and exact stdin frames, profile and explicit routing, `db init`,
`db status`, every database recovery command, `vault create`, encrypted-label
`vault list`, `vault status`, and `vault rename`. Assert no plaintext canary
reaches store-observed public fields, stdout/stderr, arguments, profiles, or
anchors.

- [ ] **Step 6: Run focused CLI verification**

Run:

```sh
pnpm exec vitest run apps/cli/test/database-session.test.ts apps/cli/test/database-commands.test.ts apps/cli/test/local-secrets.test.ts apps/cli/test/local-vault-cli-view.test.ts
pnpm --filter kavrix typecheck
pnpm --filter kavrix build
```

Expected: all commands pass.

- [ ] **Step 7: Commit the database session and commands**

```sh
git add apps/cli/src apps/cli/test vitest.config.ts
git commit -m "feat(cli): manage multiple encrypted vaults"
```

### Task 9: Explicit version 2 migration and command compatibility

**Files:**

- Create: `apps/cli/src/database-migration.ts`
- Create: `apps/cli/test/database-migration.test.ts`
- Modify: `apps/cli/src/database-commands.ts`
- Modify: `apps/cli/src/local-vault-cli.ts`
- Modify: `vitest.config.ts`

**Interfaces:**

- Consumes: existing legacy `LocalVaultDocument`, Task 8 database session, protected source/destination files, and secret input.
- Produces: `migrateLegacyVaultToDatabase()` and `migrate database` command.

- [ ] **Step 1: Write copy-first migration tests**

Cover Mongo and file destinations, all flat records, Unicode and maximum-length
names, empty vault, duplicate destination vault label, wrong source key,
destination conflict, interruption before publish, destination verification
failure, source preservation, destination cleanup, anchor creation, and runtime
plaintext-canary absence outside encrypted envelopes.

- [ ] **Step 2: Confirm migration tests fail**

Run: `pnpm exec vitest run apps/cli/test/database-migration.test.ts`

Expected: failure because migration is missing.

- [ ] **Step 3: Implement prepare, copy, verify, and publish**

Read both source and destination secrets in one bounded flow. Authenticate and
decrypt the legacy source locally, initialize a destination database when
explicitly requested, create one destination vault with a fresh VRK, preserve
every record value and timestamp, decrypt the staged destination, compare exact
canonical record names/values/counts, and only then report success. Never alter
or delete the source.

- [ ] **Step 4: Preserve flat command behavior**

When a database profile is active, existing `put/get/list/view/search/stats/has/
rename/remove` and doctor commands resolve the selected vault through
`DatabaseSession`. Database key and recovery operations use the `db key` and
`db recovery` subtrees; legacy vault-bound key and recovery commands remain on
the existing version 2 path. Ambiguous invocations fail with a usage error
rather than guessing a format.

- [ ] **Step 5: Run migration and connected-flow regressions**

Run:

```sh
pnpm exec vitest run apps/cli/test/database-migration.test.ts apps/cli/test/local-vault-cli-view.test.ts
pnpm verify
```

Expected: the migration tests and complete repository gate pass.

- [ ] **Step 6: Commit migration compatibility**

```sh
git add apps/cli/src apps/cli/test vitest.config.ts
git commit -m "feat(cli): migrate legacy vaults into databases"
```

### Task 10: Packed acceptance, documentation, and release gates

**Files:**

- Create: `acceptance/pre-ci/database-container/run.js`
- Modify: `package.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `apps/cli/scripts/smoke-packed-package.js`
- Modify: `README.md`
- Modify: `docs/README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/cli-reference.md`
- Modify: `docs/data-model.md`
- Modify: `docs/implementation-status.md`
- Modify: `docs/local-database.md`
- Modify: `docs/security-testing.md`
- Modify: `docs/threat-model.md`

**Interfaces:**

- Consumes: every prior task.
- Produces: `acceptance:database-container`, platform-matrix CI evidence, user documentation, and final package proof.

- [ ] **Step 1: Write the packed acceptance runner**

Pack and install Kavrix into an isolated temporary directory with a dedicated npm
cache. Generate runtime-random passphrases and a plaintext canary. Exercise:

1. file profile creation and selection;
2. database initialization;
3. two vault creations with encrypted labels;
4. independent credential writes and reads;
5. switching to a second local database and proving key mismatch rejection;
6. switching back and proving both original vaults remain intact;
7. legacy v2 migration into a third database;
8. wrong-database key, stale anchor, tampered catalog, and conflict failures;
9. package/private-path/plaintext scans; and
10. cleanup after pass, failure, SIGINT, and SIGTERM.

The runner must attempt every cleanup target, restore npm cache state, aggregate
operation and cleanup failures, and emit success only after cleanup completes.

- [ ] **Step 2: Confirm acceptance fails before wiring**

Run: `node acceptance/pre-ci/database-container/run.js`

Expected: failure at the first unavailable database command.

- [ ] **Step 3: Wire the acceptance gate and CI**

Add:

```json
"acceptance:database-container": "node acceptance/pre-ci/database-container/run.js"
```

Run it after `pnpm verify` on supported Windows, macOS, and Linux matrix entries.
Add a disposable MongoDB replica-set integration job when a CI service can
provide transactions; do not claim Mongo integration from mocked tests.

- [ ] **Step 4: Update documentation factually**

Document database keys versus vault keys, multi-vault hierarchy, profile
contents, Mongo routing metadata, local two-file sharing, explicit migration,
transaction requirement, rollback anchors, recovery boundaries, and current
limitations. Keep future user sharing commands marked unimplemented until their
later plan passes.

- [ ] **Step 5: Run the complete final gate**

Run:

```sh
pnpm verify
pnpm acceptance:pre-ci
pnpm acceptance:database-container
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
git diff --check
git status --short
```

Expected: every command passes, the package allowlist contains only intended
compiled artifacts and metadata, and the worktree contains no temporary files,
plaintext canaries, caches, or unrelated changes.

- [ ] **Step 6: Commit the verified foundation**

```sh
git add .github/workflows/ci.yml README.md acceptance apps/cli/scripts package.json docs
git commit -m "test: verify encrypted database containers"
```

## Deferred plans required by the approved specification

After this foundation is merged and verified, write separate plans in this
order:

1. `encrypted-hierarchy`: environments, groups, items, typed fields, and flat
   command projection.
2. `user-identities-and-grants`: Ed25519/X25519 identity files, sealed grants,
   discovery, and reader/editor/owner revision verification.
3. `vault-revocation-and-ownership`: VRK rotation, remaining-member regrant,
   signed ownership transfer, and rollback integration.
4. `multivault-operational-acceptance`: complete Mongo recipient flows,
   revocation races, Windows ACL evidence, migration drills, docs, and package
   security proof.
