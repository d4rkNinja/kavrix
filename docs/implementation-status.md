# Implementation Status

Last reviewed: 2026-08-14

This file records implementation evidence, not architectural intent. Kavrix is
still **not approved for real credentials**: the security-critical libraries and
server are substantial and first-release ownership, reporting, authorization,
and operational acceptance gates remain. The public `creds` executable now
composes the command-only initialization, unlock/lock, encrypted mutation,
online-sync, redacted read, guarded-copy, and device-management surface; the
full packed online journey and later acceptance scenarios still require their
recorded gates.

## Status definitions

- **Planned**: required or designed, but no implementation evidence exists.
- **In progress**: concrete implementation exists, but a required integration,
  platform, composition, security-review, or acceptance gate remains.
- **Verified**: the named scope exists and its stated tests passed in the recorded
  environment. Verification does not extend beyond that scope.

## Foundation and cryptographic core

| Scope                                                                                                                                         | Status      | Evidence                                                                                                                                                                                                                       | Remaining limitation                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture, threat model, cryptography, data model, security testing, enrollment, release, self-hosting, performance, and TUI documentation | In progress | The documents exist and were reviewed with their owning implementations                                                                                                                                                        | Final CLI composition and the end-to-end acceptance record must still be reconciled                                                     |
| Strict ESM TypeScript workspace                                                                                                               | Verified    | Exact Node 24.19.0/pnpm 11.21.0 frozen install, format, ESLint, project-reference typecheck, build, and repository tests pass                                                                                                  | Every release commit must repeat the exact-SHA remote cross-platform gates                                                              |
| Canonical runtime schemas and branded identities                                                                                              | Verified    | `packages/schemas`; 63 tests after backup/attachment transport additions; branch-specific AAD, bounded attachments, item-value states, device/API, and sync contracts                                                          | A future wire change requires coordinated compatibility/migration evidence                                                              |
| Dynamic fields, notes, templates, name resolution, and lossless migrations                                                                    | Verified    | `packages/core`; aggregate validation and archive/remove/restore/conversion interruption tests pass                                                                                                                            | Production CRUD composition does not yet invoke every policy                                                                            |
| Portable/recovery/device key generation, HKDF slots, and portable-key rotation                                                                | In progress | `packages/crypto` checkpoint/digest tests and `apps/cli` rotation tests cover generated/imported replacement files, same-VRK wrapping, checkpoint tamper rejection, resume, payload preservation, and plaintext-canary absence | Real SQLite journal/Windows ACL execution is blocked in this managed environment; CI, remote integration, and full release gates remain |
| Argon2id passphrase slots                                                                                                                     | Verified    | Async built-in Node 24.19 Argon2; serialized floors and pre-allocation runtime ceilings are tested                                                                                                                             | Calibration, progress UI, and cross-machine timing evidence remain                                                                      |
| XChaCha20-Poly1305 envelopes and typed AAD                                                                                                    | Verified    | Tamper, transplant, wrong-key, identity/version, and expected-context tests pass                                                                                                                                               | JavaScript/native/WASM memory erasure remains best effort                                                                               |
| Random VRK/group/item/attachment hierarchy and wrapping                                                                                       | Verified    | Isolation, unwrap binding, rewrap, and unchanged-payload tests pass                                                                                                                                                            | Full application-level rotation execution and UI are not composed                                                                       |
| Slot lifecycle and authenticated rotation checkpoints                                                                                         | In progress | Last-current-slot protection; source/replacement digests; ordered authenticated checkpoint transcripts; durable journal contract; pending/active/revoked crash-resume state-machine coverage                                   | Managed Windows ACL helper blocked the SQLite durability test; remote/CI acceptance remains                                             |
| Attachment secretstream, staged persistence, and HTTPS transfer                                                                               | Verified    | Bounded incremental secretstream, final-tag/manifest validation, hidden staging, atomic Mongo finalize, strict authenticated upload/download, retry, and parent-lifecycle tests pass                                           | Public vault CLI upload/download composition remains                                                                                    |
| Password/passphrase generators and TOTP                                                                                                       | Verified    | `packages/core`; unbiased password policy tests, offline EFF-list passphrases (82.72-bit default), and all RFC 6238 SHA-1/256/512 vectors; 107 core tests pass on Node 24.19                                                   | The public commands are non-vault utilities; storing generated values still needs unlocked-vault composition                            |

## API, storage, synchronization, and platform adapters

| Scope                                                                                                     | Status      | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Remaining limitation                                                                                                                                                         |
| --------------------------------------------------------------------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MongoDB ciphertext-only records, indexes, transactions, tombstones, attachments, and change feed          | In progress | `packages/storage`; unit suite passes 69/69, and the isolated MongoDB 8.3 replica-set run passes 64/66 integration tests, including ciphertext-only writes, attachment lifecycle, and snapshot/restore paths                                                                                                                                                                                                                                                                                                                             | Two existing backup/restore expectation failures remain in the local MongoDB 8.3 run; hosted topology and the full #48 result remain separate release evidence               |
| Device-token authentication, bootstrap, invites, enrollment, revocation, and global credential uniqueness | In progress | `apps/api`; unit suite passes 140/140, and the isolated MongoDB 8.3 replica-set run passes 15/17 integration tests covering bootstrap, attachment transport, service composition, sync rollback, and authorization concurrency                                                                                                                                                                                                                                                                                                           | Two existing Mongo authorization update-path conflicts remain in the local MongoDB 8.3 run; CI must rerun the exact operational acceptance command at the implementation SHA |
| Production API/Mongo migration, startup compatibility, readiness, and two-process acceptance              | In progress | Issue #75 adds versioned `_kavrix_schema_state` migration/preflight tooling, read-only production startup validation, `/ready` 200/503 dependency behavior, a bounded shell-free gate, and a real local MongoDB 8.3 replica-set run covering two API processes, authentication, sync, attachments, an opaque backup snapshot, and redacted logs                                                                                                                                                                                          | The pinned GitHub Mongo job and exact-SHA release evidence remain to be run; schema rollback is forward-only and documented, not automatic                                   |
| Opaque sync pull/push, retries, conflicts, and rollback detection                                         | Verified    | `packages/sync` plus API/storage/client tests; ordered pagination, durable idempotency, explicit conflict, cross-vault, rollback, delete, and exact-current restore cases pass                                                                                                                                                                                                                                                                                                                                                           | Full remote production CLI synchronization acceptance remains                                                                                                                |
| Durable local ciphertext cache, cursor, offline queue, and durable conflict ledger                        | In progress | `packages/local-store`; real Node SQLite/WAL, v3-to-v4 migration, crash/reopen, schema-tamper, corruption, capacity, receipt-pruning, atomic-publication, profile, canary, and Windows ACL tests pass; issue #31 production coverage verifies offline opaque mutations, and issue #32 coverage verifies redacted conflict persistence, revision-bound accept-remote/keep-local resolution, retry/restart durability, and no payload exposure                                                                                             | SQLite is synchronous and not encrypted; remote retry/reopen acceptance and Unix-native evidence remain                                                                      |
| HTTPS client snapshot and local read session                                                              | Verified    | `packages/client`; real loopback HTTP, bounded response, tamper, AAD, lock/zeroize, group-cascade, delete/restore, and capacity tests; coverage exceeds 90% statements and 87% branches                                                                                                                                                                                                                                                                                                                                                  | Durable cache, native session-token composition, and public CLI injection remain                                                                                             |
| Native device/session keychain                                                                            | In progress | `packages/keychain`; ordinary package suite passes 34/34 with 4 opt-in tests skipped; issue #53's explicit Windows native gate runs all 4 real Credential Manager cases but this managed session returns the generic operating-system credential-store failure                                                                                                                                                                                                                                                                           | macOS Keychain and Linux Secret Service evidence has not run locally; Windows native-store capability remains unavailable in this session                                    |
| Protected portable key-file I/O                                                                           | In progress | `packages/key-files`; canonical v1 parsing, authenticated protected files, binding checks, bounded reads, path/link/ACL/atomic-write tests, and `apps/cli/test/production-portable-key-files.test.ts` cover production unprotected/protected selection, required unbound fresh-init binding, filesystem-error handling, and byte wiping; issue #53 adds an opt-in generated-key permission/link acceptance file                                                                                                                          | Managed Windows ACL helper blocks the local unit suite and opt-in acceptance; Unix-native mode/FIFO evidence remains unrun on this workstation                               |
| Safe child-process runner                                                                                 | Verified    | `packages/runner`; 41 actual-child tests, ignored stdin, bounded/redacted stdout/stderr, timeout/abort, cross-chunk and truncation-boundary redaction; >93% statement coverage                                                                                                                                                                                                                                                                                                                                                           | A malicious child or descendant can exfiltrate through channels outside Kavrix's control; Windows process-tree termination has OS limits                                     |
| Secure clipboard policy and native backends                                                               | In progress | `packages/clipboard`; unit suite passes 32/32; values use stdin only, compare-before-clear, and generation-safe timers; issue #53's explicit Windows clipboard snapshot/copy/guarded-clear/restore integration passes 1/1                                                                                                                                                                                                                                                                                                                | macOS/Linux clipboard evidence has not run locally; the real integration remains intentionally double-opt-in and requires exclusive clipboard ownership                      |
| Authenticated encrypted backup/import/export                                                              | In progress | `packages/import-export`, `packages/client`, and `packages/storage` implement bounded HMAC framing, deterministic snapshots, hidden protocol-v2 staging, exact sealed readback verification, receipt-bound publish/finalize, and the known-v1 acceptance source; issues #41–#44 add protected create-only streaming, non-publishing verification, protected injected restore composition, and v1 history/audit semantic opening/publication with source cleanup, replay/uncertain mapping, future-version handling, and canary coverage. | The current workspace has no live exact-discovery Mongo result. Complete Mongo target wiring, packed restore exposure, and managed Windows ACL acceptance remain.            |

## CLI and TUI

Issues #39 and #40 are implemented locally on branches
`feat/issue-39-device-list-revoke` and `feat/issue-40-device-remember-forget`:
the public CLI now lists hash-free device metadata and requires explicit
confirmation for device revocation; API/Mongo revocation atomically invalidates
target sessions and denies revoking the last active device. The CLI also
composes native-keychain-only remember/forget operations with separate API
session locators and exact slot targeting. Focused CLI/API, production-port,
client, schema, and slot-lifecycle tests pass. The remote issues remain open
because external push/PR/closure actions are not authorized in this run.

Issue #41 is implemented locally on `feat/issue-41-backup-create`: the public
catalog now exposes bounded `backup create` with pre-unlock protected
destination validation, authenticated create-only streaming, snapshot cleanup,
and redacted receipts. The current CLI source is the durable local opaque
vault/group/item state and still refuses unsupported attachment/history/audit
source records; the complete Mongo snapshot adapter remains in the
storage/operator boundary.

Issue #42 is implemented locally on `feat/issue-42-backup-verify`: the public
catalog now exposes non-publishing `backup verify` with protected source
preflight, active remembered-device authentication, bounded framing/graph
verification, safe error codes, and wiped archive/root-key buffers. It proves
outer archive integrity only; semantic history/audit decryptability and restore
publication remain later gates. The remote issue remains open because external
push/PR/closure actions are not authorized in this run.

Issue #43 is implemented locally on `feat/issue-43-backup-restore`: the
dependency-injected catalog accepts an opaque archive/vault/slot selector and
renders redacted restore receipts, while
`executeProtectedEncryptedBackupRestore` validates the protected source before
delegating to explicit isolated-target and semantic-verification ports. It
maps exact committed replay and `BACKUP_COMMIT_UNCERTAIN`, preserves the
archive/target instruction on uncertain publication, and wipes the bounded
archive buffer. The packed executable omits restore until a safe target
adapter is configured; the remote issue remains open because external
push/PR/closure actions are not authorized in this run.

Issue #44 is implemented locally on `feat/issue-44-semantic-backup-restore`:
the known-v1 restore verifier now opens item-key history snapshots and
root-key key-slot audit payloads with strict identity/revision/hash and
slot/action validation, canonical payload bounds, duplicate-family checks, and
generic corruption handling. Authenticated future payload versions remain
explicitly unsupported. Receipt algebra and Mongo publication now include both
families; focused client/schema/import-export/storage tests pass. The remote
issue remains open because external push/PR/closure actions are not authorized
in this run.

Issue #45 is implemented locally on `feat/issue-45-basic-vault-acceptance`: the
source-level production CLI composition now passes the single-device Scenario A
journey through real SQLite/client adapters and an opaque HTTPS fixture, including
init, unlock, encrypted group/item/field mutations, sync, masked show, guarded
copy, lock, reopen, rename, archive/restore, and field reads. The generated
package build and Windows launcher smoke pass, while a packed online-vault
journey, native-keychain evidence, and the later interruption/recovery/backup/
canary scenarios remain separate gates. The remote issue remains open because
external push/PR/closure actions are not authorized in this run.

Issue #46 is implemented locally on `feat/issue-46-interruption-recovery`: real
SQLite and native protected-state acceptance coverage now injects failures after
durable mutation acknowledgement, active-batch persistence, remote commit,
reconciliation, protected completion, and pull application. The matrix proves
offline queue preservation, exact batch replay, response-loss deduplication,
monotonic cursor recovery, and reopened redacted conflict resolution; all eight
cases pass with opaque transport payload and local-row canary assertions. The
existing client lifecycle suite remains the evidence for the durable init
journal boundaries. The remote issue remains open because external
push/PR/closure actions are not authorized in this run.

Issue #47 is implemented locally on `feat/issue-47-device-b-acceptance`: the
real-adapter acceptance flow creates encrypted data on Device A, issues a
canonical invite, enrolls Device B from a distinct empty home, synchronizes and
decrypts the public field locally while keeping the sensitive field redacted,
then revokes Device B and proves a fresh session is denied. The opaque control-
plane fixture validates bootstrap, invite, enrollment, key-slot, sync, and
revocation contracts; request bodies/headers, server state, and both homes pass
portable-key, VRK, username, and password canary scans. The focused test passes
on managed Windows Node 24.13.1; the remote issue remains open because external
push/PR/closure actions are not authorized in this run.

Issue #48 is implemented locally on `feat/issue-48-backup-restore-acceptance`:
the real-Mongo acceptance gate seeds a source database through the canonical
restore coordinator, creates and authenticates an archive from
`MongoBackupSource`, restores it into a separate empty target with an equal
rollback anchor, compares exact opaque records, reads active/deleted/restored
records through a fresh sync snapshot, and scans the archive and durable BSON
for plaintext and credential canaries. No live result is claimed in this
workspace because `KAVRIX_MONGODB_URI` is not configured; the remote issue
remains open because external push/PR/closure actions are not authorized in
this run.

Issue #49 is implemented locally on `feat/issue-49-whole-system-security-acceptance`:
the CLI and TUI terminal boundaries now consume 8-bit C1 CSI/string commands and
neutralize Unicode line separators, with focused hostile-content regressions
passing. The basic production-backed acceptance now generates a runtime canary,
records and scans opaque HTTP, command arguments/environment, stdout/stderr,
captured logs, local artifacts, encrypted backup bytes, completion, and
post-lock clipboard state across the documented encodings. The full flow could
not reach its first `init` assertion in this managed workstation because the
existing Windows ACL helper returns `KEY_FILE_UNSAFE` and native credential-store
operations also fail; no passing end-to-end local canary result is claimed. The
remote issue remains open because external push/PR/closure actions are not
authorized in this run.

Issue #50 is verified locally on `feat/issue-50-exact-verification-gates` at
`205ef4894e08c3a3b17cec636318700e778fedc2`. On Windows PowerShell with Node
`v24.13.1` and pnpm `11.21.0`, workspace build, format check, and project-reference
typecheck pass. Root ESLint fails with 18 existing violations in
`apps/cli/src/production/recovery.ts`, `apps/cli/test/cli.test.ts`, and
`apps/cli/test/production-recovery.test.ts`; no lint rule or assertion was
changed. The configured full unit test and V8 coverage commands both hit the
240-second wrapper timeout after the managed Windows ACL/native-keychain failures
in key-files, sealed-store, production lifecycle, and the #49 basic canary flow.
Storage integration fails closed in all four suites because
`KAVRIX_MONGODB_URI` is unset; the API integration gate reports that MongoDB
integration is required. This is a recorded verification result, not a passing
release gate. The remote issue remains open because external push/PR/closure
actions are not authorized in this run.

Issue #51 is implemented locally on `feat/issue-51-package-security-gates`:
the npm audit initially found high-severity `nanoid <3.3.18` through the Vitest /
Vite / PostCSS graph, so the workspace override and lockfile were updated to
`nanoid@3.3.18`; the rerun reports no known vulnerabilities. The public package
dry-run emits only the expected compiled bundle, generated chunks, declaration,
SBOM, license, manifest, and README; its build-time reviewed dependency and
CycloneDX/hash validations pass. The authoritative offline package smoke passes
on Windows, including generated launcher execution, public catalog/completion,
hidden-command refusal, canary absence, lazy-loading checks, sealed status,
writer-lease handling, and cleanup. The first dry-run after the lock update
needed a frozen dependency-link repair because the managed pnpm environment had
purged `apps/cli/node_modules`; no tracked source was removed. The remote issue
remains open because external push/PR/closure actions are not authorized in this
run.

Issue #52 is implemented locally on `feat/issue-52-mongo-exact-discovery-gate`.
The storage package now has a bounded, shell-free exact-discovery gate matching
the API gate: it requires a nonblank `KAVRIX_MONGODB_URI`, recursively discovers
and explicitly invokes every `*.integration.ts` file, validates the Vitest JSON
report for complete all-passed coverage with no pending/todo/failed tests, and
prints only generic failure output. The focused storage gate tests pass 7/7;
the complete storage unit suite passes 69/69; storage typecheck, build, targeted
ESLint, and Prettier checks pass. Both storage and API integration commands
fail closed with `MongoDB integration environment is required.` when the
required URI is absent. A live transaction-capable Mongo run was intentionally
not part of that issue's verification because `KAVRIX_MONGODB_URI` was unset;
the later #75 operational run uses a separate isolated replica-set process and
does not change the absent-environment fail-closed result recorded here. The
remote issue remains open because its external push/PR/closure actions have not
been performed.

Issue #53 is implemented locally on `feat/issue-53-platform-acceptance`. The
new `pnpm platform:acceptance` command requires explicit keychain, key-file,
clipboard, and exclusive-session flags, invokes the exact three native
integration files through a bounded shell-free child, and rejects skipped or
incomplete Vitest reports with generic output. Its adversarial contract suite
passes 11/11. The ordinary clipboard package suite passes 32/32 and the real
Windows clipboard integration passes 1/1. The ordinary keychain package suite
passes 34/34 with its four opt-in tests skipped when disabled, but all four
explicit Windows native-keychain tests fail with the generic operating-system
credential-store error in this managed session. The key-files package remains
blocked by the existing managed Windows ACL helper (33 failures, 5 passes, 2
platform-skipped unit tests), and the new opt-in key-file integration fails at
the same ACL setup. No fallback was added and no platform-wide pass is claimed.
The remote issue remains open because external push/PR/closure actions are not
authorized in this run.

Issue #75 is implemented locally on `feat/issue-75-operational-acceptance`.
Migration owns the baseline MongoDB validator/index contract and records a
strict schema state; production API startup validates that state without DDL.
The `/ready` route reports only a generic dependency state, and the acceptance
gate creates a generated isolated database before running migration and the
exact operational file. On Windows Node `v24.13.1`, a temporary MongoDB 8.3
single-member replica set passed the full gate: two production API processes,
HTTPS-proxy readiness, bootstrap/session authentication, sync push/pull,
attachment streaming, a transaction-consistent opaque backup snapshot, bounded
logs, and URI/plaintext-canary absence. CI now runs the same gate after the
storage and API integration jobs. The remote issue remains open pending
pull-request merge and an exact-SHA GitHub run.

| Scope                                                                                                                          | Status      | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Remaining limitation                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Dynamic Ink TUI                                                                                                                | In progress | `packages/tui`; real Ink/React package, wide three-pane and narrow models, dynamic field editor, multiple notes, search/help/palette/conflicts, sanitized ASCII/control handling, safe reveal/copy intents; 21 tests and >90% statement coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The public executable does not yet supply real unlocked-vault, save, clipboard, reauthentication, and lock use cases |
| CLI parser, redacted show/copy renderer, init/device contracts, masked/framed stdin, completion, and public security utilities | In progress | `apps/cli`; parser and production-port tests cover protected/unprotected `init --key-file` import with unbound binding and staged passphrase frames, `sync conflicts list`, revision-bound `sync conflicts resolve`, fresh-home `recover` and `device join`, key-slot lifecycle, crash-resumable `key rotate` generated/imported replacement paths, authenticated device-invite create/list/revoke with one-time token output, device list/revoke with explicit confirmation and last-device denial, native-keychain-only device remember/forget with separate session locators, and protected isolated backup-restore composition through explicit target/verification ports; the public package exposes password/passphrase generation, TOTP, protected portable-key creation, crash-safe init, existing-vault `connect`, fresh-home `recover`/`device join`, masked unlock/lock, invite/device management, `key slot`, `key rotate`, local group/credential CRUD, dynamic field operations, encrypted note CRUD, redacted credential inspection (`creds show`), guarded clipboard copy (`creds copy`), guarded credential reveal (`creds reveal`), scriptable field retrieval (`creds get`), vault synchronization (`creds sync`), and bounded backup create/verify; owned inputs are wiped best effort | Real SQLite/Windows ACL rotation acceptance, packed restore target adapter, and other vault gates remain             |
| Public `creds show`, `copy`, `reveal`, `get`, `set`, CRUD, notes, backup, run, device, and TUI workflows                       | In progress | Canonical lower-level ports and adapters exist; issues #37–#40 compose authenticated invite/device management, crash-resumable join, and native-keychain remember/forget, while issues #41–#44 compose bounded backup create/verify, injected isolated restore, and v1 history/audit semantic verification; the packed executable still omits restore, run, and TUI until their production target/use-case adapters are complete                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The remaining commands must be composed end to end; no production mock or unavailable fallback may be advertised     |
| Vault init/connect/recover/unlock/lock/status lifecycle                                                                        | In progress | `apps/cli/src/production/*` and the packed smoke compose and test crash-safe public `init`, non-destructive existing-vault `connect`, fresh-home `recover`, masked `unlock` (remembered device, protected key file, passphrase) plus `unlock --check`, `lock`, and one locked/offline `status`; production connect tests cover exact profile binding, active device-slot validation, opaque sync-engine bootstrap, retry-safe profile persistence, resource cleanup, and secret wiping; production recovery tests cover empty-home gating, portable-slot authentication before device-slot publication, protected device/profile persistence, first sync, preflight ordering, cancellation, and secret wiping; production unlock/lock tests cover leases, cleanup, and managed clipboard clear                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Full later device management and post-connect online CRUD remain absent                                              |
| Encrypted durable local cache/offline queue and conflict resolution                                                            | In progress | The restrictive SQLite adapter persists only canonical opaque records, cursors, pending mutations, active batches, replay receipts, and bounded conflict audit rows; issue #31 verifies offline enqueue/retry composition, issue #32 verifies redacted list/resolve commands, and issue #46 verifies real-adapter interruption, response-loss, monotonic-cursor, and conflict recovery across reopen; public status, init, unlock/lock, and local group/credential mutation use the global writer lease and profile/sync stores                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Packed interruption journey and managed native acceptance remain                                                     |

## Verification and release readiness

| Gate                                                          | Status        | Evidence / limitation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scoped unit/property/adversarial tests                        | Verified      | The split workspace test groups pass on Windows Node 24.13.1; focused coverage generally exceeds the repository thresholds, with the candid Windows-only key-file exception above                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Whole-system plaintext canary and hostile terminal acceptance | In progress   | Issue #49 CLI boundary and TUI sanitizer regressions pass; the acceptance scanner covers HTTP, process, output, logs, local artifacts, backup, completion, and clipboard surfaces with a runtime canary and encoded-form checks                                                                                                                                                                                                                                                                                                                                                                                                     | The real acceptance flow is blocked before `init` by managed Windows ACL/native credential-store failures; #48's Mongo scan still needs `KAVRIX_MONGODB_URI`                                                                             |
| Current repository-wide build/format/lint/type/test/coverage  | In progress   | Issue #50 exact local run at `205ef4894e08c3a3b17cec636318700e778fedc2`: build, format, and project-reference typecheck pass on Windows Node 24.13.1; root ESLint reports 18 existing violations; full test and V8 coverage commands each hit the 240-second wrapper timeout after managed Windows ACL/native-keychain failures; the #52 storage and existing API gates now fail closed before child execution when Mongo is absent                                                                                                                                                                                                 | No complete local unit/coverage threshold result, live Mongo result, exact-Node 24.19 result, or cross-platform result is claimed                                                                                                        |
| Real MongoDB plaintext-canary and restore semantics           | Pending rerun | A production-crypto known-v1 acceptance fixture, real-Mongo source cases, and the #48 source-to-archive-to-isolated-target gate cover the three supported archived slot types, sealed semantic readback, v1 history/audit opening/publication, exact receipt publication, replay/response-loss/rollback, fresh-client current-record reads, and raw canary scans. Issue #52 supplies exact recursive discovery, explicit Vitest invocation, zero-skip validation, bounded execution, and generic output for storage; #75 separately proves the API operational migration and opaque backup-source smoke on a temporary replica set. | The full #48 source-to-archive-to-isolated-target result has not been run at this SHA; Task 5B writer fencing, packed target-adapter composition, broader Scenario A-H scanning, and managed/topology coverage remain. SB-01 stays open. |
| Dependency audit                                              | Verified      | Exact lockfile audit after manifest reconciliation reports no known vulnerabilities; only reviewed `esbuild` lifecycle scripts are allowed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Registry advisories remain time-dependent and must be rerun for release                                                                                                                                                                  |
| Independent security review                                   | Verified      | Combined-tree adversarial review found and then verified the runner truncation/redaction fix; no known Critical or High issue remains in the milestone boundaries                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | A public release still requires its final artifact/deployment review                                                                                                                                                                     |
| Cross-platform CI                                             | Pending rerun | The #54 workflow now declares five architecture entries for Linux x64/arm64, macOS x64/arm64, and Windows x64 plus the seven-entry Node range matrix; the local release-policy regression suite proves those exact records and required smoke steps                                                                                                                                                                                                                                                                                                                                                                                 | No GitHub Actions run exists for the changed workflow at the implementation SHA; the historical run predates this matrix change and cannot be reused                                                                                     |
| Declared Node range verified across operating systems         | In progress   | `engines.node` is `>=24.12.0 <25 \|\| >=25.1.0`; a startup capability probe backs the version check, and the packed smoke test now executes the npm-generated launcher (`creds.cmd` via `cmd.exe` on Windows, the `.bin` symlink elsewhere). The #54 workflow contract covers Node 24.12.0 on Linux/Windows/macOS, Node 25.1.0 on Linux/Windows, and Node 26.7.0 on Linux/Windows; locally the three runtime-sensitive packages pass on Windows Node 24.13.1 (250 tests)                                                                                                                                                            | The runtime-range job has not run on GitHub at the changed SHA, so cross-platform runtime behavior remains unverified                                                                                                                    |
| Public npm package preparation                                | In progress   | `kavrix` manifest, deterministic ESM entry/chunks, per-artifact CycloneDX 1.6 SBOM coverage, exact archive allowlist, offline install/bin smoke, OIDC/provenance workflow, README/LICENSE/SECURITY/release contract; issue #51 updates the audited nanoid override to 3.3.18, current npm audit reports no known vulnerabilities, `pack:check` emits the exact allowlist, and the Windows Node 24.13.1 packed smoke passes launcher, canary, lazy-load, sealed-status, lease, and cleanup checks                                                                                                                                    | Only locked status is bundled from the vault surface; Node 24 may emit its own SQLite `ExperimentalWarning` unless externally disabled; native-keychain/cross-platform status evidence and publication controls remain                   |
| Public release                                                | Planned       | No tag, GitHub release, npm publication, or visibility change has been performed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Requires all Definition-of-Done gates and explicit external release actions                                                                                                                                                              |

## Current security limitations

- A compromised local host, administrator/root process, same-user malware,
  keylogger, terminal recorder, screen capture, clipboard monitor, or memory
  scraper can observe secrets while they are actively used.
- JavaScript strings and runtime/native/WASM copies cannot be reliably zeroized;
  mutable owned buffers are wiped best effort.
- A malicious server can delete or withhold records. Retained-device rollback
  anchors detect only the documented monotonic-revision cases.
- The current public executable does not yet provide complete enrollment,
  online-sync, credential-read, copy, and device workflows. Its locked local status,
  standalone generators, TOTP, completion, version, protected portable-key
  creation, and local group/credential mutation are operational, but this narrow
  evidence must not be interpreted as a supported vault release.
- Native opt-in evidence in this session is Windows x64: the clipboard
  snapshot/copy/guarded-clear/restore integration passes, while Credential
  Manager and ACL-backed key-file acceptance fail because this managed session
  cannot use those native helpers. The last recorded GitHub OS matrix passed
  portability and packed-install gates, but it predates the #54 matrix change
  and must be rerun at the changed SHA; it does not prove macOS/Linux native
  keychain or clipboard integrations and does not produce release artifacts.

When advancing a row, record the production files, observable commands,
environment, and material limitation. Downgrade it immediately if a later change
invalidates that evidence.
