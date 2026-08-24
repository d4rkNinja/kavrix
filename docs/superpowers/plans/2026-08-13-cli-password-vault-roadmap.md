# Command-Line Password Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a production-composed `creds` CLI that initializes, unlocks, stores, synchronizes, retrieves, copies, recovers, and backs up credentials without exposing plaintext outside the unlocked client.

**Architecture:** Keep `apps/cli` limited to parsing, protected input, composition, and sanitized rendering. Reuse `packages/client`, `core`, `crypto`, `local-store`, and `sync`; the API/MongoDB remain ciphertext-only. Each invocation acquires the writer lease, performs one bounded operation, locks, clears owned secret buffers, and exits.

**Tech Stack:** Strict ESM TypeScript 6, Node.js `>=24.12.0 <25 || >=25.1.0`, pnpm 11.21.0, Commander, Zod, Vitest, SQLite/WAL, XChaCha20-Poly1305, Argon2id, HTTPS, MongoDB.

## Global Constraints

- Execute tasks strictly in numeric order; Task N+1 starts only after Task N tests pass and its commit exists.
- TUI work is excluded; never import `@kavrix/tui` into the public executable.
- Never persist, transmit, log, render by default, or put in argv plaintext keys, passphrases, tokens, or credential values.
- Accept secrets only through masked prompts, protected files, native keychains, or bounded explicit stdin.
- Preserve runtime schemas, authenticated envelopes, resource bounds, rollback anchors, stable exit codes, and terminal sanitization.
- Never weaken validation, assertions, canary tests, cleanup, or zero-knowledge boundaries to pass a gate.
- No tag, release, npm publication, deployment, or real-credential use is authorized by this plan.

## Status Ledger

| Order | Deliverable                                                      | Status                       | User outcome              |
| ----: | ---------------------------------------------------------------- | ---------------------------- | ------------------------- |
|     0 | Help/version/completion/generators/TOTP/key-create/locked status | ✅ Verified                  | Standalone utilities      |
|     1 | Template-publication crash recovery                              | 🔴 One test failing          | Trustworthy sync recovery |
|     2 | `init/resume/cancel`                                             | 🟡 Lower layers exist        | Create a vault            |
|     3 | Unlock/lock                                                      | 🟡 Lower layers exist        | Open/close vault safely   |
|     4 | Mutation contracts and adapters                                  | 🟡 Client service exists     | Encrypted writes          |
|     5 | Group/credential CRUD commands                                   | ❌ Missing                   | Store/edit passwords      |
|     6 | `show/copy/reveal`                                               | 🟡 Read/catalog layers exist | Retrieve passwords        |
|     7 | `sync` and offline/conflict status                               | 🟡 Engine exists             | Synchronize safely        |
|     8 | Portable-key recovery                                            | 🟡 Crypto/file layers exist  | Recover after local loss  |
|     9 | Device lifecycle                                                 | 🟡 API/catalog layers exist  | Add/revoke devices        |
|    10 | Backup/verify/restore                                            | 🟡 Libraries exist           | Disaster recovery         |
|    11 | End-to-end security acceptance                                   | ❌ Missing                   | Prove basic CLI journey   |
|    12 | Cross-platform release gates and PR                              | 🟡 Historical only           | Reviewed artifact         |

`creds run`, attachments, history/audit browsing, template authoring, interactive conflict editing, and advanced rotation commands are deferred until after Task 12.

---

### Task 1: Finish Template-Publication Recovery

**Files:** Modify `packages/sync/src/engine.ts`, `packages/sync/src/validation.ts`, `packages/sync/test/sync-engine.test.ts`, `packages/client/test/vault-client-session.test.ts`; test `packages/sync/test/sync-engine-recovery-matrix.test.ts`, `packages/local-store/test/rollback-anchor-recovery.test.ts`.

**Interfaces:** Consume `OutboundObservation` and `SyncLocalStorePort.reconcileOutboundObservation()`; produce exact contiguous staging and crash/reopen confirmation with no duplicate publication.

- [ ] Reproduce: `.\node_modules\.bin\vitest.cmd run packages/local-store/test/rollback-anchor-recovery.test.ts -t "reopens a template publication"`; expect `SyncProtocolError` before the injected local failure.
- [ ] Trace replay start, required-through sequence, accepted sequences, staged sequences, and final cursor without logging ciphertext.
- [ ] Preserve this contract and fix the owning engine or fixture:

```ts
const firstRequired = observation.replayFromServerSequence + 1;
const lastRequired = observation.requiredThroughServerSequence;
// Stage every sequence in [firstRequired, lastRequired] exactly once.
```

- [ ] Run: `.\node_modules\.bin\vitest.cmd run packages/sync/test/sync-engine.test.ts packages/sync/test/sync-engine-recovery-matrix.test.ts packages/local-store/test/rollback-anchor-recovery.test.ts packages/client/test/vault-client-session.test.ts`; expect all pass and zero replayed publications.
- [ ] Commit: `git add packages/sync packages/local-store/test/rollback-anchor-recovery.test.ts packages/client/test/vault-client-session.test.ts && git commit -m "fix(sync): complete template publication recovery"`.

### Task 2: Compose Production Initialization

**Files:** Create `apps/cli/src/production/initialize.ts`, `apps/cli/test/production-initialization.test.ts`; modify `environment.ts`, `ports.ts`, `bin.ts`, and `package.test.ts`.

**Interfaces:** Consume `VaultInitializationCoordinator`, SQLite journal/profile store, `SecretBackend`, sensitive display; produce:

```ts
interface ProductionInitializationCommands {
  initialize(input: { serverUrl: string; keyFilePath: string }): Promise<void>;
  resume(operationId: string): Promise<void>;
  cancel(operationId: string): Promise<void>;
}
```

- [ ] Test one profile, restrictive key file, protected session, one bootstrap request, interruption/resume, and plaintext-canary absence; expect failure because the production factory is absent.
- [ ] Implement the factory using the existing coordinator; acquire the lease, refuse ambiguous/non-empty state, persist only through owning ports, and clear key/token buffers in `finally`.
- [ ] Wire `init`, `init resume`, and `init cancel` into `bin.ts` with existing sanitized exit behavior.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/initialization.test.ts apps/cli/test/production-initialization.test.ts apps/cli/test/sensitive-display.test.ts`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): compose production vault initialization"`.

### Task 3: Compose Unlock and Lock

**Files:** Create `apps/cli/src/production/unlock.ts`, `apps/cli/test/production-unlock.test.ts`; modify `secret-input.ts`, `production/ports.ts`, `catalog.ts`, `bin.ts`.

**Interfaces:** Produce an invocation-scoped runner:

```ts
type UnlockMethod =
  | { kind: 'remembered-device' }
  | { kind: 'portable-key-file'; path: string }
  | { kind: 'passphrase-stdin' };
interface UnlockedCommandRunner {
  run<T>(
    method: UnlockMethod,
    operation: (session: VaultClientSession) => Promise<T>,
  ): Promise<T>;
}
```

- [ ] Test remembered-device, protected-file, wrong-key, corruption, dual operation/cleanup failure, lease release, and generic errors.
- [ ] Implement profile resolution → protected input → local unlock → operation → unconditional lock/clear/release.
- [ ] Expose `creds unlock --check` (unlock then immediately lock) and production `creds lock`; do not create a daemon.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/production-unlock.test.ts apps/cli/test/secret-input.test.ts apps/cli/test/production-secret-backend.test.ts packages/client/test/vault-client-session.test.ts`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): compose guarded vault unlock"`.

### Task 4: Define and Adapt Encrypted Mutations

**Files:** Create `apps/cli/src/mutation-contracts.ts`, `apps/cli/src/production/mutations.ts`, tests `mutation-contracts.test.ts`, `production-mutations.test.ts`; modify `contracts.ts`, `production/ports.ts`.

**Interfaces:** Extend CLI ports with:

```ts
interface CliMutationPorts {
  createGroup(input: { name: string }): Promise<{ groupId: string }>;
  createCredential(input: {
    groupQuery: string;
    name: string;
  }): Promise<{ itemId: string }>;
  setField(input: {
    groupQuery: string;
    credentialQuery: string;
    fieldQuery: string;
    value: Uint8Array;
  }): Promise<void>;
  archiveCredential(groupQuery: string, credentialQuery: string): Promise<void>;
  restoreCredential(groupQuery: string, credentialQuery: string): Promise<void>;
}
```

- [ ] Test strict Zod bounds, unknown keys, controls, owned byte secrets, revision conflict, idempotent replay, and plaintext-canary absence in SQLite/transport/logs.
- [ ] Implement schemas with inferred types, then adapt `VaultMutationService` through `UnlockedCommandRunner`; wipe `value` in `finally`.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/mutation-contracts.test.ts apps/cli/test/production-mutations.test.ts packages/client/test/vault-mutation-service.test.ts packages/local-store/test`.
- [ ] Typecheck: `.\node_modules\.bin\tsc.cmd -p apps/cli/tsconfig.json --pretty false`.
- [ ] Commit: `git add apps/cli packages/client/test/vault-mutation-service.test.ts && git commit -m "feat(cli): compose encrypted credential mutations"`.

### Task 5: Expose Basic Credential CRUD

**Files:** Modify `apps/cli/src/catalog.ts`, `cli.ts`, `render.ts`, `bin.ts`; create `apps/cli/test/credential-commands.test.ts`.

**Interfaces:** Add exactly:

```text
creds group create <name>
creds credential create <group-query> <name>
creds credential set <group-query> <credential-query> <field-query> --secret-stdin
creds credential archive <group-query> <credential-query>
creds credential restore <group-query> <credential-query>
```

- [ ] Test parser bounds, secret rejection in argv/environment, exactly one stdin frame, sanitized labels, stable exits, and static completion without runtime names.
- [ ] Add catalog descriptors and connect handlers to Task 4 ports; acquire secrets after validation and wipe them after one call.
- [ ] Render fixed receipts containing only safe labels/opaque IDs.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/credential-commands.test.ts apps/cli/test/cli.test.ts apps/cli/test/secret-input.test.ts apps/cli/test/package.test.ts`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): expose basic credential commands"`.

### Task 6: Compose Show, Copy, and Reveal

**Files:** Modify `contracts.ts`, `production/ports.ts`, `catalog.ts`, `render.ts`, `bin.ts`; create `apps/cli/test/direct-access-production.test.ts`.

**Interfaces:** Reuse `VaultClientSession.show()` and add `reveal(...): Promise<{ label: string; value: Uint8Array }>`.

- [ ] Test masked show, Unicode/alias/ID ambiguity, copy without output, compare-before-clear, redirected reveal rejection, reauthentication, and hostile terminal strings.
- [ ] Activate production `show`; replace `copy` unavailable only where a clear mechanism safely survives process exit, otherwise fail closed.
- [ ] Implement guarded reveal with interactive stdout by default and wipe owned bytes after rendering.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/direct-access-production.test.ts apps/cli/test/sensitive-display.test.ts packages/clipboard/test packages/client/test/vault-client-session.test.ts`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): compose guarded credential access"`.

### Task 7: Expose Sync and Offline/Conflict Status

**Files:** Modify `contracts.ts`, `production/ports.ts`, `catalog.ts`, `bin.ts`; create `apps/cli/test/production-sync.test.ts`.

**Interfaces:** Add `sync(): Promise<CliStatus>` and `creds sync [--json]` using `VaultClientSession.synchronize()`.

- [ ] Test online success, offline queue preservation, response loss, rollback, protocol error, and unresolved conflict without record output.
- [ ] Implement unlock → synchronize → redacted status → lock; JSON contains only fields allowed by `cliStatusSchema`.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/production-sync.test.ts packages/sync/test packages/client/test/vault-client-session.test.ts packages/local-store/test`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): expose rollback-safe synchronization"`.

### Task 8: Implement Portable-Key Recovery

**Files:** Create `apps/cli/src/production/recovery.ts`, `apps/cli/test/production-recovery.test.ts`; modify `catalog.ts`, `bin.ts`, `docs/portable-key-and-device-enrollment.md`.

**Interfaces:** Produce `recover({serverUrl, vaultId, keyFilePath}): Promise<{deviceId: string}>`.

- [ ] Test a fresh data home recovering and reading a record, plus wrong key, tampering, response loss, permissions, and leak scans.
- [ ] Implement local portable-slot authentication before enrollment completion; persist independent session/device credentials and never transmit portable key/VRK.
- [ ] Register `creds recover --server <url> --vault <id> --key-file <path>`; output only vault/device IDs.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/production-recovery.test.ts packages/key-files/test packages/client/test/portable-enrollment.test.ts packages/client/test/vault-join.test.ts`.
- [ ] Commit: `git add apps/cli docs/portable-key-and-device-enrollment.md && git commit -m "feat(cli): add portable-key vault recovery"`.

### Task 9: Complete Device Commands

**Files:** Create `apps/cli/src/production/devices.ts`, `apps/cli/test/production-devices.test.ts`; modify `contracts.ts`, `production/ports.ts`, `catalog.ts`, `bin.ts`.

**Interfaces:** Expose invite create/list/revoke, device join/list/revoke, remember, and forget using `ControlPlaneClient` and protected token storage.

- [ ] Test expiry, replay, revocation, response loss, credential collision, wrong key, last-device protection, and token absence from output/logs/argv.
- [ ] Implement durable independent successor-token reuse and protected final device-token persistence.
- [ ] Register commands with masked/exact-stdin invite input and public-metadata-only lists.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/production-devices.test.ts packages/client/test/vault-join.test.ts apps/api/test`.
- [ ] Commit: `git add apps/cli && git commit -m "feat(cli): compose device enrollment commands"`.

### Task 10: Expose Backup, Verify, and Restore

**Files:** Create `apps/cli/src/production/backups.ts`, `apps/cli/test/production-backups.test.ts`; modify `contracts.ts`, `catalog.ts`, `bin.ts`, `docs/backup-and-recovery.md`.

**Interfaces:** Consume `createEncryptedBackup`, `verifyEncryptedBackup`, `restoreEncryptedBackup`; expose `creds backup create|verify|restore`.

- [ ] Test refusal of overwrite/symlink/broad permissions/partial publication, plus tampering, wrong vault, bounds, uncertain commit, and plaintext canaries.
- [ ] Stream create to a hidden sibling temporary file, fsync, and atomically publish; verify without publishing.
- [ ] Restore only into an explicitly empty isolated database after authenticated semantic readback; never overwrite in place.
- [ ] Run: `.\node_modules\.bin\vitest.cmd run apps/cli/test/production-backups.test.ts packages/import-export/test packages/storage/test` plus the documented exact-discovery Mongo gate against a verified test URI.
- [ ] Commit: `git add apps/cli docs/backup-and-recovery.md && git commit -m "feat(cli): expose encrypted backup recovery"`.

### Task 11: Prove the Basic CLI Journey

**Files:** Create `apps/cli/test/basic-vault-acceptance.test.ts`, `plaintext-canary-acceptance.test.ts`; modify `docs/implementation-status.md`, `README.md`, `docs/cli-reference.md`.

**Interfaces:** Consume Tasks 1–10 through the packed executable.

- [ ] Scenario A: init → create group/item → set username/password through stdin → sync → redacted show/copy → lock → reopen.
- [ ] Scenario B: interrupt each durable init/mutation boundary, resume exact identities, preserve queued work, and avoid duplicates.
- [ ] Scenario C: fresh-home recovery and Device B enrollment decrypt Device A data without server-side key/plaintext exposure.
- [ ] Scenario D: encrypted backup → verify → isolated restore → rollback check → fresh client read.
- [ ] Run both tests and byte/string scans across requests, MongoDB, SQLite, logs, argv, environment captures, backups, and completion; expect zero plaintext canaries.
- [ ] Update docs factually and commit: `git add apps/cli/test README.md docs && git commit -m "test(cli): prove basic password vault lifecycle"`.

### Task 12: Run Release Gates and Raise the PR

**Files:** Modify only when evidence changes: `docs/implementation-status.md`, `docs/release.md`, packaging workflow/scripts.

**Interfaces:** Consume the exact Task 11 commit; produce reviewed PR evidence, not a release.

- [ ] Run local gates:

```powershell
.\node_modules\.bin\tsc.cmd -b --pretty false
.\node_modules\.bin\eslint.cmd . --max-warnings 0
.\node_modules\.bin\prettier.cmd --check .
.\node_modules\.bin\vitest.cmd run
```

- [ ] Run coverage, audit, pack allowlist, packed smoke, real Mongo canaries, Windows native gates, and Linux/macOS/Windows CI across the declared Node range; record exact skips/failures without suppressing them.
- [ ] Perform final security review of zero-knowledge boundaries, input, permissions, recovery, rollback, redaction, cleanup, dependencies, and package contents; Critical/High findings block readiness.
- [ ] Update evidence and commit: `git add docs/implementation-status.md docs/release.md && git commit -m "docs: record command vault acceptance evidence"`.
- [ ] Push: `git push -u origin codex/fix-template-publication-recovery`.
- [ ] Open a PR targeting `main` with scope, invariants, tests, limitations, and explicit confirmation that no release/publication occurred.

## Completion Definition

The command-only milestone is complete only when Tasks 1–12 are checked and committed in order, the packed executable proves initialization → unlock → create/set → sync → redacted show/copy → lock → reopen → recovery → encrypted backup/restore, and the exact candidate passes cross-platform security gates. Until then, Kavrix remains not approved for real credentials.
