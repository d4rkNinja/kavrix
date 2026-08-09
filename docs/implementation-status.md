# Implementation Status

Last reviewed: 2026-08-10

This file records evidence, not intent. The architecture and security documents
describe the target; they do not make a feature complete. Kavrix is not ready
for real credentials: no end-user CLI/API/TUI flow or production persistence
adapter is verified.

## Status definitions

- **Planned**: required or designed, but no implementation evidence exists.
- **In progress**: concrete implementation exists, but a required integration,
  platform, or acceptance gate remains.
- **Verified**: the named scope exists and its stated tests/review passed in the
  recorded environment. Verification does not extend beyond that scope.

## Foundation and cryptographic core

| Scope                                                                                                                    | Status      | Evidence                                                                                                                   | Remaining limitation                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Architecture, threat model, cryptographic design, data model, and security test plan                                     | In progress | `docs/*.md`; reviewed alongside the foundation contracts                                                                   | Must evolve with API, storage, CLI, TUI, and platform adapters                                                     |
| Strict ESM TypeScript workspace                                                                                          | Verified    | Node 24.19.0, pnpm 11.21.0: frozen install, format, ESLint, project typecheck, and build passed on 2026-08-10              | Cross-platform CI has not run on GitHub yet                                                                        |
| Canonical runtime schemas, semantic brands, typed AAD, sync and attachment contracts                                     | Verified    | `packages/schemas`; 51 tests; independent schema/core review returned GO with no Critical/High/Medium findings             | MongoDB validators and wire-compatibility fixtures are Phase 3 work                                                |
| Dynamic fields, explicit value states, repeatable IDs/lifecycle, notes, name resolution, and template migration policies | Verified    | `packages/core`; 39 tests; lossless interruption/resume and archive identity regressions covered                           | No CLI/TUI use case consumes these policies yet                                                                    |
| Portable and recovery key generation, encoding, checksums, and parsing                                                   | Verified    | `packages/crypto/test/keys.test.ts`; exact-runtime workspace gate                                                          | Do not entrust real keys until surrounding product flows are complete                                              |
| Portable-key file codecs                                                                                                 | In progress | Canonical bound/unbound v1 golden tests and protected/unprotected round trips pass                                         | Filesystem symlink, ownership, Unix mode, Windows ACL, and atomic-write adapter is not implemented                 |
| HKDF-SHA-256 portable, recovery, and device slots                                                                        | Verified    | Independent salts, same-VRK multi-slot tests, wrong-key failures, context binding, and security re-review passed           | Native keychain-backed device enrollment is not implemented                                                        |
| Async Node `crypto.argon2` passphrase slots                                                                              | Verified    | Node 24.19.0 exact-runtime test gate; serialized floors and pre-auth resource ceilings covered                             | Calibration/user-progress UI and cross-machine vectors remain required before release                              |
| XChaCha20-Poly1305-IETF envelopes and expected-context AAD                                                               | Verified    | Whole-envelope transplant, tamper, wrong-key, and identity/version swap tests; independent crypto review returned GO       | JavaScript/native memory clearing is best effort                                                                   |
| Random VRK/group/item/attachment hierarchy and wrapping                                                                  | Verified    | Hierarchy isolation, unwrap context, rewrap, and unchanged-payload tests pass                                              | Full application rotation workflow is not implemented                                                              |
| Multi-slot lifecycle and last-current-slot protection                                                                    | Verified    | Validated `VaultRecord` aggregate and current-key-version revocation tests pass                                            | API/device revocation transaction is Phase 3 work                                                                  |
| Authenticated rotation checkpoints                                                                                       | In progress | Source-record digests, one-step replacement digests, processed transcript, forgery/reorder tests pass                      | Storage must durably persist and read-back verify each replacement before advancing                                |
| Attachment secretstream encryption/decryption and staged commit                                                          | In progress | Owned-buffer, canonical manifest, ordering/final-tag, JSON codec, abort/commit, and bounds tests pass                      | Storage adapter must keep staging invisible and atomically finalize; manifest must be encrypted before persistence |
| Incremental attachment storage contract                                                                                  | Verified    | Hidden begin/write/finalize/abort protocol; shared order/retry/final/aggregate policy; generic attachment commits rejected | Real MongoDB/API partial-visibility and crash-recovery integration tests remain required                           |

## API, storage, CLI, and TUI

| Scope                                                                                     | Status  | Remaining requirement                                                                |
| ----------------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| MongoDB encrypted-record storage, validation, indexes, and concurrency                    | Planned | Implement against the frozen ciphertext-only ports and test with real MongoDB        |
| Device-token authentication and single-use enrollment invites                             | Planned | Hash-only storage, expiry, replay, revocation, rate limits, and canary tests         |
| Opaque sync pull/push, idempotency, conflicts, and rollback detection                     | Planned | Preserve protected local highest revision and prove no plaintext reaches server/logs |
| Encrypted local cache/offline queue                                                       | Planned | Restrictive platform paths/permissions and corruption/recovery tests                 |
| CLI init/connect/unlock/lock/status                                                       | Planned | Masked input and lifecycle acceptance tests                                          |
| Direct `creds show`, `copy`, `reveal`, `get`, and `set`                                   | Planned | Stable redacted output, reauthentication, clipboard clearing, and argv/stdin safety  |
| Dynamic schema-driven TUI                                                                 | Planned | Real Ink interface, resize/narrow/ASCII/accessibility and terminal-injection tests   |
| Keychain, import/export, backup/recovery, TOTP, generator, references, history, reminders | Planned | Implement real platform/use-case adapters without plaintext fallback                 |

## Verification and release readiness

| Gate                                                                                                 | Status      | Evidence / limitation                                                                                                                                     |
| ---------------------------------------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit, property, and adversarial foundation tests                                                     | Verified    | Node 24.19.0/pnpm 11.21.0: 151 tests in 17 files passed                                                                                                   |
| Coverage thresholds                                                                                  | Verified    | 91.46% statements, 86.67% branches, 95.97% functions, 92.74% lines; configured thresholds were not lowered                                                |
| Formatting, lint, strict typecheck, and build                                                        | Verified    | `pnpm verify` passed on the exact minimum runtime                                                                                                         |
| Dependency audit                                                                                     | Verified    | `pnpm audit --audit-level high`: no known vulnerabilities on 2026-08-10                                                                                   |
| Internal independent security review                                                                 | Verified    | Schema/core and crypto final gates returned GO with no current Critical/High/Medium findings in their foundation scope                                    |
| Supply-chain and public-repository scaffolding                                                       | In progress | Full action SHAs, exact Node, frozen install, public-only dependency review, README/LICENSE/metadata, fail-closed absent CLI publishing                   |
| GitHub cross-platform CI                                                                             | In progress | Workflow covers Ubuntu, macOS, and Windows; no remote run evidence yet                                                                                    |
| Public `kavrix` npm package                                                                          | Planned     | Real CLI manifest/bin, reviewed archive, SBOM/canary scan, exact-artifact OIDC publication, npm ownership, public repo and protected environment required |
| Real MongoDB/API tests, plaintext-canary scans, acceptance scenarios, restore drills, and benchmarks | Planned     | No evidence yet                                                                                                                                           |

## Current security limitations

- The host is trusted only while uncompromised; unlocked plaintext can be read by
  sufficiently privileged local malware, debuggers, terminal capture, or screen
  recording.
- JavaScript, V8, operating-system, and WASM copies make zeroization best effort.
- Secretstream state cleanup relies on pinned `libsodium-wrappers` 0.8.4
  internals and must be re-reviewed on upgrades.
- Rotation and attachment atomicity cannot be proven by cryptographic code; the
  storage implementation and crash/retry tests must enforce the documented
  persist/verify/finalize ordering.
- The API must never import `@kavrix/crypto`; its zero-knowledge claim remains
  unproven until the real server and database canary tests pass.

When advancing a row, record the exact production files, commands, environment,
date, and material limitation. Downgrade a row immediately if a later change
invalidates its evidence.
