# Packed CLI lifecycle acceptance implementation plan

> **For agentic workers:** Execute this plan task-by-task in the current issue branch. Keep the change limited to issue #45; later interruption, recovery, backup, and plaintext-canary scenarios belong to #46–#49.

**Goal:** Prove and repair the single-device command-only lifecycle through the production CLI composition, including initialization, unlock, encrypted mutations, sync, masked show, clipboard copy, lock, and reopen.

**Architecture:** Use the real CLI catalog, production SQLite/profile/secret/clipboard adapters, and client cryptographic/session composition. The acceptance test supplies an opaque local control-plane fixture at the network boundary so the test server stores only validated vault records, mutations, and ciphertext-bearing change records; it never decrypts or asserts plaintext server state. A small terminal-wiring fix gives initialization the caller's actual terminal streams, and the production session exposes its existing in-process copy capability through the public port so environment cleanup can clear the clipboard before exit.

**Tech Stack:** Strict ESM TypeScript, Vitest, Node streams, `node:sqlite`, `@kavrix/client`, `@kavrix/crypto`, `@kavrix/local-store`, `@kavrix/schemas`, and the existing CLI production adapters.

## Global Constraints

- Preserve the zero-knowledge boundary: the API/control-plane fixture and SQLite store contain only opaque encrypted records and hashes.
- Never place portable keys, recovery keys, backend passphrases, or credential values in argv, environment, logs, or rendered output.
- Keep sensitive initialization output on a TTY-only dedicated stream and clear it after acknowledgement.
- Use canonical runtime schemas for every test-server request, response, mutation, and change record.
- Keep the public CLI output stable and redacted; copy returns only its existing label/expiry receipt.
- Do not add MongoDB imports or production mocks to `apps/cli`.
- Do not include interruption/retry/conflict (#46), fresh-home recovery/device B (#47), backup/restore (#48), or whole-system canary (#49) work.

---

### Task 1: Make production initialization use the real terminal safely

**Files:**

- Modify: `apps/cli/src/catalog.ts` to pass command runtime streams into the production initialization request.
- Modify: `apps/cli/src/cli.ts` and `apps/cli/src/catalog.ts` context types to expose stdin/stderr only for composition; keep stdout rendering unchanged.
- Modify: `apps/cli/src/production/initialize.ts` to accept terminal streams and construct a non-process-identity TTY proxy for the sensitive display.
- Test: `apps/cli/test/production-initialization.test.ts` and `apps/cli/test/sensitive-display.test.ts`.

**Interfaces:**

- `ProductionInitializationRequest.terminal?: Readonly<{ input: Readable; output: Writable }>`.
- `CliCommandContext.stdin` and `CliCommandContext.stderr` are the runtime streams supplied by `createProgram`.
- The proxy preserves `isTTY`, forwards writes/errors, and is closed by the initialization operation; a non-TTY still fails before material is rendered.

- [x] **Step 1: Add a failing composition test** that runs the production initialization path with a TTY-like input/output pair and asserts the sensitive display is reached instead of the generic non-interactive failure. The Scenario A acceptance harness now supplies that TTY-like boundary.
- [x] **Step 2: Run the focused initialization test** with `.\node_modules\.bin\vitest.cmd run --root . apps/cli/test/production-initialization.test.ts apps/cli/test/sensitive-display.test.ts`; the affected matrix exposed the production composition gaps before the fix.
- [x] **Step 3: Implement the stream plumbing and safe output proxy** without changing the direct sensitive-display refusal of ordinary process stdout/stderr.
- [x] **Step 4: Rerun the focused initialization/display tests** and verify all existing refusal and cleanup assertions remain green.

### Task 2: Expose copy through the production port

**Files:**

- Modify: `apps/cli/src/production/ports.ts` to add the existing `VaultClientSession.copy` operation to `ProductionVaultSession` and route `CliUseCasePorts.copy` through `withUnlocked`.
- Test: `apps/cli/test/production-ports.test.ts`.

**Interfaces:**

- `ProductionVaultSession.copy(groupQuery: string, credentialQuery: string, fieldQuery: string, options?: CredentialCopyOptions): Promise<CredentialCopyReceipt>`.
- The port must unlock, perform the bounded copy, call `session.lock()` in the existing cleanup path, and let environment disposal clear the guarded clipboard.

- [x] **Step 1: Add a failing test** using the existing session factory seam, asserting `ports.copy('group', 'credential', 'password')` calls the session copy method and then locks it.
- [x] **Step 2: Run the focused production-port test** and confirm the current implementation returns `CLI_UNAVAILABLE`.
- [x] **Step 3: Implement the one-line session-interface addition and the `withUnlocked` delegation**, preserving generic cleanup/error aggregation.
- [x] **Step 4: Rerun the focused test** and assert only the public copy receipt is returned; no field value appears in the receipt or output.

### Task 3: Add Scenario A acceptance coverage with an opaque local control plane

**Files:**

- Create: `apps/cli/test/basic-vault-acceptance.test.ts`.
- Modify: `apps/cli/README.md`, `docs/cli-reference.md`, and `docs/implementation-status.md` only for behavior directly demonstrated by the passing test.

**Interfaces:**

- The test invokes the real CLI catalog with real production adapters and a TTY-aware runtime.
- The local control-plane fixture validates bootstrap, session, vault, pull, and push payloads using `@kavrix/schemas`; it assigns monotonic opaque change records and returns only schema-valid sync responses.
- A test-only `SecretInputPort` supplies protected backend prompts and initialization confirmations without exposing them to argv/environment; field mutation invocations use `NodeSecretInput` with `--value-stdin`.

- [x] **Step 1: Write the failing end-to-end scenario** covering:
      `init --confirmation-stdin`, `unlock --check`, `group create`, `credential create`, `field add --value-stdin` for username, `field add --value-stdin` for password, `sync`, `show`, `copy`, `lock`, and a fresh-process-equivalent reopen/status plus masked show.
- [x] **Step 2: Add adversarial assertions** that the show output contains `[REDACTED]` and never the username/password, the copy receipt contains no value, captured API bodies contain no canary plaintext, and all temporary SQLite/profile/sealed resources close after the lifecycle.
- [x] **Step 3: Run the exact issue gate** with `.\node_modules\.bin\vitest.cmd run --root . apps/cli/test/basic-vault-acceptance.test.ts` and confirm the current init/copy gaps fail the scenario.
- [ ] **Step 4: After Tasks 1–2 pass, implement only the acceptance harness/documentation updates**; keep the server opaque and bounded, and assert every response through canonical schemas.
- [x] **Step 5: Rerun the exact issue gate** and the affected CLI production test files.

### Task 4: Review and commit the issue

**Files:**

- Review: all files changed by Tasks 1–3; no unrelated files.

- [x] **Step 1: Run formatting, typecheck, targeted lint, and `git diff --check`.**
- [x] **Step 2: Run the affected CLI test matrix and the packed package build/smoke command.**
- [x] **Step 3: Inspect the diff for plaintext canaries, process-argument secrets, production mock imports, and accidental public-surface changes.**
- [ ] **Step 4: Create one local commit** with message `test(cli): prove packed single-device lifecycle (#45)`.

**Spec coverage self-review:** Scenario A command ordering, production adapters, TTY-gated initialization, sync, redacted show, clipboard cleanup, lock/reopen, and plaintext boundary assertions are covered. The later scenarios and whole-system canary are intentionally absent and remain assigned to #46–#49.
