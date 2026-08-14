# Fresh-home recovery and second-device acceptance implementation plan

> **For agentic workers:** Execute this plan task-by-task in the current issue branch. Keep the change limited to issue #47; interruption recovery belongs to #46 and backup/restore/canary scanning belong to #48/#49.

**Goal:** Prove that a second device can enroll from a fresh home, decrypt Device A's synchronized data locally, and is denied after revocation without any plaintext crossing the server boundary.

**Architecture:** Add one focused acceptance test using the real CLI production composition, two real SQLite homes, and native-protected test-owned OS seams. The test control plane validates canonical opaque schemas and implements only the routes required by initialization, invite enrollment, sync, and device revocation.

**Tech Stack:** Strict ESM TypeScript, Vitest, Node streams/filesystem, `@kavrix/client`, `@kavrix/crypto`, `@kavrix/local-store`, `@kavrix/schemas`, and the existing CLI production adapters.

## Global Constraints

- Preserve zero knowledge: the control plane stores only opaque encrypted vault, group, item, and key-slot records.
- Never place portable keys, VRKs, session successors, device secrets, or field plaintext in argv, environment, logs, request bodies, SQLite plaintext, or rendered output.
- Use the canonical schemas for every test-server request, response, change, mutation, invite, enrollment, and device record.
- Use separate fresh homes for Device A and Device B and refuse cleanup outside the test-owned prefixes.
- Keep production behavior unchanged unless the focused observable test proves an owning-layer defect.
- Do not add MongoDB imports, production mocks, or new cryptographic behavior.

---

### Task 1: Build the two-device opaque control-plane harness

**Files:**

- Create: `apps/cli/test/device-b-acceptance.test.ts`
- Review: `apps/cli/test/basic-vault-acceptance.test.ts`, `apps/cli/test/production-recovery.test.ts`, `packages/client/src/control-plane-client.ts`, `packages/client/src/vault-join.ts`

**Interfaces:**

- `DeviceAcceptanceControlPlane.fetch(input, init): Response` is the global fetch boundary.
- `execute(home, arguments, secretFrames): Promise<{ stdout: string; stderr: string; code: number }>` runs the real CLI with `CREDS_HOME=home`.
- `assertNoPlaintext()` scans captured request bodies and server-owned opaque state for the username, password, portable key, and VRK encodings.

- [x] **Step 1: Create the test-owned native entry and clipboard seams** using the same `vi.importActual` pattern as the existing packed acceptance test; clone and wipe mutable protected bytes on reset.
- [x] **Step 2: Add schema-valid route handlers** for bootstrap, session, vault, invite issue/redeem, enrollment completion, key-slot publication, sync pull/push, and device revoke; authenticate active session hashes and consume invites once.
- [x] **Step 3: Add bounded fresh-home creation and cleanup** under the real temporary directory, closing every opened adapter and refusing unverified recursive cleanup targets.
- [x] **Step 4: Run the new file once** to verify the harness compiles and expose only the missing acceptance behavior.

### Task 2: Prove Device A creation and opaque synchronization

**Files:**

- Modify: `apps/cli/test/device-b-acceptance.test.ts`

**Interfaces:**

- The real CLI commands are `init`, `group create`, `credential create`, two `field add --value-stdin` calls, `sync`, and `device invite create --stdout`.
- The fixture records change sequences and returns encrypted records without a decryption helper.

- [x] **Step 1: Run production `init` in Device A's home** and capture the displayed portable key only inside the test's bounded secret-input seam.
- [x] **Step 2: Create the group, credential, public username, and sensitive password** through the existing production commands, asserting success output contains no secret value.
- [x] **Step 3: Synchronize and issue a one-time invite** with the existing production device command, retaining only the explicit invite frame needed by Device B.
- [x] **Step 4: Assert all captured A-side request bodies and server state are canary-free** before Device B begins.

### Task 3: Prove fresh-home Device B enrollment, decryption, and revocation

**Files:**

- Modify: `apps/cli/test/device-b-acceptance.test.ts`

**Interfaces:**

- Device B runs `device join --server <url> --vault <id> --invite-stdin --portable-key-stdin --json` with one exact `[invite, portable-key]` secret batch.
- Device B reads through `show` using its protected remembered device slot; Device A revokes using `device revoke <device-id> --confirm`.

- [x] **Step 1: Start with a distinct empty Device B home** and run the real public join composition; assert the receipt contains only the vault/device identifiers.
- [x] **Step 2: Run Device B `show`** and assert the public username is readable, the sensitive password is `[REDACTED]`, and neither the password nor portable key appears in output.
- [x] **Step 3: Revoke Device B from Device A** and run a new Device B sync; assert a nonzero authentication result with generic sanitized output and no secret leakage.
- [x] **Step 4: Scan both homes and the control-plane fixture** for plaintext canaries, portable-key text, VRK bytes, and field values; assert cleanup closes stores and removes the test homes.

### Task 4: Verify and document the issue

**Files:**

- Modify: `apps/cli/README.md`
- Modify: `docs/implementation-status.md`
- Modify: this plan

- [x] **Step 1: Run focused Vitest, affected tests, typechecks, lint, format, and `git diff --check`.**
- [x] **Step 2: Run the CLI build and packed package smoke test.**
- [x] **Step 3: Review the diff for plaintext canaries, argv/env secrets, production mocks, weakened assertions, and unrelated issue work.**
- [x] **Step 4: Create one local commit** with message `test(cli): prove second-device recovery (#47)`; external push/PR remains blocked without authorization.
