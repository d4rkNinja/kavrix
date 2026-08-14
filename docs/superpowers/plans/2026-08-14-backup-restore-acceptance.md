# Encrypted backup and isolated restore acceptance implementation plan

> **For agentic workers:** Execute this plan task-by-task in the current issue branch. Keep the change limited to issue #48; whole-repository scanning belongs to #49 and packed Mongo target wiring is intentionally out of scope.

**Goal:** Prove real Mongo-backed archive creation, protected verification, isolated restore, rollback freshness, fresh-client reads, and plaintext-canary absence.

**Architecture:** Extend the existing real-Mongo canonical restore integration with one explicit source-to-archive-to-isolated-target acceptance flow. Reuse production adapters and the canonical encrypted fixture; add no production Mongo or cryptographic behavior.

**Tech Stack:** Strict ESM TypeScript, Vitest, MongoDB replica-set integration, `@kavrix/import-export`, `@kavrix/client`, `@kavrix/storage`, and the existing canonical restore fixture.

## Global Constraints

- Use two fresh randomly named Mongo databases and never overwrite or merge a target.
- Keep the archive, Mongo documents, test output, and process boundaries free of plaintext, credentials, and root-key encodings.
- Use the existing canonical schemas, verifier, restore coordinator, and storage adapters.
- Preserve the packed CLI boundary: no raw MongoDB URI, Mongo import, or public restore descriptor.
- Keep cleanup bounded to test-created databases and wipe fixture-owned key material through existing fixture helpers.

---

### Task 1: Add the real source-to-target acceptance flow

**Files:**

- Modify: `packages/storage/integration/mongo-backup-source.integration.ts`

**Interfaces:**

- `MongoBackupSource.open` supplies the source vault and opaque records.
- `createEncryptedBackup` and `verifyEncryptedBackup` create and authenticate the archive.
- `MongoBackupRestoreStore` and `restoreEncryptedBackup` publish into the empty target.
- `MongoVaultStorage` and `OpaqueVaultSnapshot` provide fresh-client reads.

- [x] **Step 1: Seed a fresh source database** with the canonical known-v1 fixture through the existing restore coordinator.
- [x] **Step 2: Create and authenticate an archive from the real source snapshot**, retaining only opaque records and the bounded test verifier key.
- [x] **Step 3: Restore the archive into a separate empty target** with an equal highest-seen revision anchor and assert a fresh receipt.
- [x] **Step 4: Compare source and target vault/record state**, read exact current records through a fresh sync snapshot, and assert target revision freshness.
- [x] **Step 5: Scan archive and both durable databases for plaintext and credential canaries** and assert staged entries are gone.

### Task 2: Document and verify the issue

**Files:**

- Modify: `docs/implementation-status.md`
- Modify: `apps/cli/README.md`
- Modify: this plan

- [x] **Step 1: Run the focused integration gate when Mongo is available; otherwise run the affected non-Mongo suites and record the exact missing prerequisite.**
- [x] **Step 2: Run storage/client/import-export/CLI typechecks, build, lint, format, and diff checks.**
- [x] **Step 3: Review the diff for production-boundary violations, secret leakage, target overwrite behavior, and unrelated issue work.**
- [x] **Step 4: Create one local commit** with message `test(storage): prove isolated backup restore (#48)`; external push/PR remains blocked without authorization.
