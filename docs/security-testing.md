# Security Testing

> Design status: this is the required verification plan. It does not claim that
> any test or CI job exists or passes. Executed evidence must be recorded in
> [implementation-status.md](./implementation-status.md) with exact file names
> and commands/results.

## Principles

- Cryptography, secret-boundary, and storage behavior is developed test-first.
- Tests assert observable security properties, not implementation details alone.
- A failing security assertion blocks release; it is never weakened to make a
  build green.
- Fixtures use clearly fake values generated for that test. Real credentials are
  prohibited in source, snapshots, logs, screenshots, and CI variables.
- A dependency audit is useful evidence, not a security review.
- Unit tests do not substitute for a real MongoDB, terminal, keychain, operating
  system, or packaged-artifact test where behavior depends on one.
- Randomized tests must record a safe replay seed. They must not print generated
  secret values on failure.

## Evidence levels

| Level             | Meaning                                                                   |
| ----------------- | ------------------------------------------------------------------------- |
| Designed          | Requirement is documented; no implementation evidence                     |
| Unit verified     | Focused tests pass for the referenced module on the stated runtime        |
| Integrated        | Real adapters/process boundaries pass, including failure paths            |
| Platform verified | Packaged behavior passes on each claimed OS/architecture                  |
| Security reviewed | Threat model and implementation received a recorded human security review |

A feature may be marked `Verified` only when its required level is met and the
status table links real code/tests. "Test file exists," mocks passing, or a clean
dependency audit is insufficient.

## Cryptographic unit tests

### Portable and recovery keys

- Generate exactly 256 bits through an injected/verified CSPRNG boundary.
- Encode/decode canonical `cvk1_` form and version dispatch.
- Verify checksum and compare it in constant time where applicable.
- Reject wrong prefix/case, padding, alternate alphabet, whitespace, Unicode
  lookalikes, truncation, extension, duplicate key-file headers, invalid byte
  length, oversized input, and unsupported version.
- Prove Windows CRLF and Unix LF file transport do not alter key bytes.
- Prove generated portable and recovery keys are independent.
- Prove neither raw nor encoded key appears in serialized slot/record objects,
  logs, error messages, environment, or argv.

### KDFs

- Check HKDF-SHA-256 against [RFC 5869 test vectors](https://datatracker.ietf.org/doc/html/rfc5869#appendix-A).
- Same portable key, salt, and exact info yields the same 32-byte KEK across
  supported platforms.
- Different salt, info context, slot type, or key input yields a different KEK.
- Reject missing, unknown, duplicated, out-of-bounds, or non-canonical HKDF
  parameters.
- Check Argon2id implementation against
  [RFC 9106 test vectors](https://datatracker.ietf.org/doc/html/rfc9106#section-5.3).
- Run the vectors and serialized-parameter compatibility suite across the
  supported range; assert startup rejects Node `<24.12.0` and the excluded 25.0.x
  band, and rejects a runtime that reports a supported version but is missing or
  cannot call `crypto.argon2`/`crypto.argon2Sync`. Test the predicate at both
  edges of every boundary rather than at one admitted version.
- Serialize and restore Argon2id version, salt, memory, passes, parallelism, and
  output length exactly.
- Enforce the 64 MiB/3-pass/4-lane floor for new slots and upper allocation/time
  bounds for untrusted stored parameters.
- Verify passphrase bytes are not trimmed or silently Unicode-normalized.
- Prove production composition uses asynchronous `node:crypto` `argon2`, never
  `argon2Sync` or a native third-party Argon2 package; add a responsiveness
  test/benchmark for the TUI event loop.

### AEAD, envelopes, and AAD

- Round-trip every payload type and supported size boundary.
- Assert a fresh 24-byte nonce is requested for every encryption and that
  deterministic test randomness cannot enter production composition.
- Independently alter nonce, ciphertext, authentication tag, algorithm ID,
  envelope version, AAD version, schema version, key version, and payload type.
- Independently swap vault, group, item, attachment, chunk, and slot IDs.
- Move valid item ciphertext/wrapped keys between items, groups, and vaults.
- Reject truncation, trailing bytes, malformed base64url, empty/oversized
  ciphertext, unknown fields that create ambiguity, and unsafe integer values.
- For every failure assert: no partial plaintext return, no plaintext output,
  generic user error, typed internal error, and canary absence in logs.
- Test canonical AAD encoding for absent/empty distinction, fixed field order,
  length prefixes, Unicode prohibition in opaque IDs, and collision-resistant
  tuple boundaries.

### Slots and hierarchy

- Generate independent random VRK, group, item, attachment, device, and recovery
  keys; fail a test if a derivation path substitutes for randomness.
- Portable, passphrase, recovery, and device slots independently wrap/unwrap the
  same VRK.
- A slot KEK cannot unwrap a different slot or key version.
- Wrong portable key, passphrase, recovery key, and device secret fail
  generically.
- Adding/changing an unlock method leaves group/item ciphertext byte-identical
  except for explicitly changed outer revision metadata.
- Prevent deletion/revocation of the last verified unlock slot.
- Do not activate a replacement until a full authenticated unwrap matches the
  current VRK.
- Best-effort clearing tests verify mutable buffers are overwritten where the
  library permits, without claiming V8-wide erasure.

### Rotation

- VRK rotation re-wraps group keys only; group rotation re-wraps that group's
  item keys only; item rotation re-encrypts only the item.
- Inject interruption before/after every checkpoint and commit marker.
- Resume each interruption idempotently and prove at least one complete valid
  path remains throughout.
- Reject stale/mixed key versions and corrupted checkpoints.
- Property-test random vault sizes and interruption sequences.
- Verify old keys are retained only for the documented migration/grace state and
  removed after verified commit.

## Domain and schema tests

- Runtime schemas are the single source of TypeScript types and reject excess
  critical fields, prototype-pollution keys, unsafe numbers, and oversized data.
- Property-test arbitrary Unicode labels/notes, repeatable values, dynamic
  schemas, select options, and item-only fields.
- Stable field keys survive label rename/reorder and are unique within scope.
- Secret default values are rejected for every field type.
- Sensitive field types default to sensitive even when the caller omits policy.
- Missing, empty, inapplicable, archived/orphaned, and unreadable values remain
  distinguishable.
- Template add/rename/reorder/requiredness/conversion migrations preserve data.
- Removing a field archives all values across many items; restore returns exact
  values; purge requires a separate operation.
- Interrupt every migration stage and resume without duplication or loss.
- Test note add/edit/view/search/pin/archive/restore/delete/reorder/duplicate and
  sensitivity changes at group and item scope.
- Validate credential references, copy sequences containing only stable keys,
  password generator policies, and TOTP against published algorithm vectors.

## Storage and API integration tests

Run against a real MongoDB instance, preferably isolated by Testcontainers where
supported. Do not use an in-memory imitation as the only evidence.

### Persistence

- Create a vault, slots, groups, items, notes, history, tombstones, and encrypted
  attachments; restart and decrypt through the client boundary.
- Assert MongoDB validators reject wrong types, unknown versions, oversized
  payloads, illegal state, and plaintext-shaped secret fields.
- Assert all required unique/query indexes exist and are actually selected for
  representative bounded queries.
- Exercise optimistic concurrency and concurrent conflicting writes.
- Exercise idempotent retry after ambiguous network completion.
- Verify transaction behavior only where the implementation depends on atomic
  multi-record state.

### API zero-knowledge boundary

- Build/dependency tests prove `apps/api` cannot import client decryption/KDF
  entry points.
- API request schemas reject portable keys, passphrases, recovery keys, KEKs,
  unwrapped VRKs, and decrypted payload shapes.
- With the complete API configuration and a MongoDB dump, a test API process has
  no function or key capable of decrypting a canary record.
- Authorization headers and bodies are absent from routine/debug logs.
- Production mode rejects insecure HTTP assumptions/configuration.
- Enforce request-size limits, pagination/cursor bounds, schema validation,
  safe query construction, rate limits, request IDs, health checks, and graceful
  shutdown.

### Device authentication and enrollment

- Device tokens and invites use independent CSPRNG bytes and only hashes persist.
- Valid invite consumes atomically and issues a distinct per-device token.
- Concurrent replay allows at most one success.
- Used, expired, revoked, malformed, wrong-vault, wrong-scope, and rate-limited
  invites fail generically.
- Token hash uniqueness, constant-time verification where applicable, scope, and
  revocation are tested.
- Same portable key on simulated Device A and B derives/unwraps locally; neither
  HTTP capture nor server storage contains that key or VRK.
- Enrollment resumes safely after failure at each network/local-persistence
  boundary.
- Duplicate device display names do not collapse opaque device identities.
- Revoked token cannot pull/push; tests state that previously decrypted data is
  not remotely erased.

### Sync, deletion, history, and backup

- Pull from cursor, pagination, monotonic sequence, idempotent push, offline
  queue, resume, and explicit conflict responses.
- Never silently last-write-wins two independent secret edits.
- Trash/restore preserves ciphertext and relationships; purge is separate.
- Best-effort rollback detection catches a server revision below the protected
  highest-seen value on the same retained device and documents cases it cannot
  catch.
- Backup creation/verification/restore authenticates manifest and every record;
  corruption, omission, duplication, reorder, truncation, and oversized entries
  fail closed.
- Restore to a clean real MongoDB instance and independently unlock with
  portable, passphrase, and recovery slots as applicable.

The known-v1 backup/recovery acceptance gate must execute every discovered
storage integration file with zero skipped, pending, todo, or focused tests. It
uses one canonical zero-history/zero-audit production-crypto graph and requires:

- independent fresh restore through archived portable-key, Argon2id passphrase,
  and recovery-key slots;
- exact `staging -> sealed -> published -> committed` evidence, committed replay
  without a fabricated receipt, and publish/finalize response-loss
  reconciliation;
- rollback anchors absent/equal (integrity/decryptability and freshness
  respectively) and a lower archive revision rejected before publication;
- authentication-only success but semantic publication failure for each opaque
  history/audit family;
- HMAC-valid inner corruption at preferences, wrapped group key, group payload,
  wrapped item key, item payload, wrapped attachment key, attachment manifest,
  and attachment stream;
- staged substitution after seal both before client readback and before storage
  publication, plus an observational no-tamper wrapper control;
- zero visible mutation and an exact aborted marker for every definite
  pre-publication failure; and
- raw archive, hidden staging BSON, committed BSON, source/change-feed output,
  errors, and captured logs free of plaintext and credential canaries.

History/audit semantic restore remains unsupported; no test may describe opaque
HMAC verification as payload decryptability. The acceptance source is present,
but the current workspace has neither `KAVRIX_MONGODB_URI` nor the generic
exact-discovery/zero-skip evidence gate, so no live pass, topology, SHA, or test
count is recorded here.

## Plaintext-canary test

The canary test is a release gate, not a grep of source fixtures alone.

1. Generate unique high-entropy canary byte strings at test runtime for every
   secret class: portable/passphrase/recovery/device credentials, each data-key
   class, field values, note/history/audit content, attachment metadata/content,
   invite, token, and MongoDB URI credentials.
2. Exercise init, enrollment, CRUD, direct show/copy/update, sync, conflict,
   backup, rotation, failure, lock, and restore.
3. Snapshot permitted encrypted/public artifacts only after all processes stop.
4. Scan raw bytes and decoded text variants (UTF-8, UTF-16LE where relevant,
   base64/base64url, JSON-escaped forms, substrings above a safe length) across:

   - MongoDB BSON/documents and indexes sampled through exports;
   - captured HTTP requests/responses and API/CLI logs;
   - local cache, configuration, lock files, temporary directories, crash output,
     backup archives, and attachment chunks;
   - stderr/stdout, error objects, test snapshots/reports, shell completion, argv,
     and environment captures;
   - packaged tarballs/archives and source maps.

5. Maintain an explicit allowlist only for intentionally decrypted test memory
   and a separately isolated guarded plaintext-export test. An unexplained match
   is a failure; do not redact the evidence and call the scan successful.
6. Ensure test failure reporters never print the canary itself; report class,
   location, encoding, and a one-way diagnostic fingerprint.

## CLI and process-boundary tests

- `creds show <group> <credential>` resolves exact ID/alias/name,
  case-insensitive exact, and unique prefix in order; ambiguity never silently
  selects a record. Cover spaces, slashes, quotes, shell metacharacters, Unicode,
  duplicate names, and PowerShell/Bash/Zsh/Fish quoting.
- Show every schema and item-only field in order; secrets remain present but
  masked. Cover missing/empty/archived/unreadable states and type-aware safe
  previews.
- Redirected output is one-shot, ANSI-free, non-interactive, and redacted.
  Versioned JSON is stable and redacted. Unsafe stdout/reveal-all paths require
  every documented guard.
- Copy exactly one field without printing it, compare-before-clear, do not erase
  unrelated newer clipboard content, and document failure as best effort. Cover
  repeatable selection, recovery-code used state, sequences, and `--no-clear`/
  headless policy.
- Update/set obtains secret values only from a masked prompt or explicit stdin.
  No secret appears in argv, shell completion, errors, history, or logs.
- Portable key and invite work through masked prompt, protected file, and
  explicit stdin; forbidden value flags do not exist.
- `creds run` uses argument arrays with `shell: false`, prints names only in dry
  run, maps only explicitly selected fields, does not create `.env`, and releases
  values after child exit. Inspect child argv and logs for absence.
- Lock, inactivity, Ctrl+C, SIGINT/SIGTERM, terminal close, offline/network
  failure, and typed exit codes leave no decrypted UI state.

## Terminal/TUI tests

- Sanitize CSI/ANSI, OSC title/clipboard/hyperlink sequences, C0/C1 controls,
  embedded NUL, bidirectional controls, raw binary, hostile URLs/paths, and very
  long values in every renderable model property.
- Test unlock, dashboard, group/schema builder, dynamic item editor, notes,
  reveal/auto-hide, copy, search, conflict, unsaved change, and lock flows.
- Test 80x24, narrower warning/routing, resize during operation, Unicode and ASCII
  fallback, keyboard focus, disabled shortcuts while typing, and Ctrl+C.
- Search stays local after unlock; secret-value search is off unless enabled for
  that session. Persisted index/drafts are encrypted.
- Snapshot tests may check layout but never contain plaintext secret fixtures.
  Behavioral terminal tests are required for cursor clearing and auto-hide.

## Key-file, filesystem, and attachment tests

- Atomic no-overwrite key-file creation; mode 0600 on Unix and user-only ACL on
  Windows before content is written.
- Reject symlinks, reparse ambiguity, wrong owner, broad ACL/mode, directories,
  devices/pipes, oversized/sparse files, duplicate headers, extra content, and
  vault/key binding mismatch.
- Passphrase-protected files enforce Argon2id floor/bounds and authenticate all
  binding headers as AAD.
- Attachment upload/download streams with bounded memory, verifies every chunk
  and manifest hash, rejects a changed header, reordered/duplicated/missing/
  appended chunks and missing final tag, rejects path traversal/reserved names,
  and removes incomplete output after failure.
- No plaintext temporary file is created by normal note edit, backup, or
  attachment flow. Explicit destinations use restrictive permissions.

## Property and fuzz testing

Use property-based tests for arbitrary dynamic schemas, Unicode labels/notes,
repeatable fields, template migration sequences, import parsers, backup
manifests, AEAD round trips, and interrupted rotation checkpoints.

Fuzz envelope, key-file, import, backup, API, and attachment parsers with hard
CPU/memory/input bounds. Expected behavior is a typed rejection without crash,
hang, unbounded allocation, partial plaintext, unsafe file output, or secret in
the error. Preserve a minimized non-secret reproducer for every defect.

## Required end-to-end scenarios

The product specification's acceptance scenarios are release gates:

| Scenario                   | Essential proof                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Email dynamic fields/notes | Lock/unlock, item-only promotion, note counts, copy/reveal/TOTP, safe rename/migration, canary-clean persistence          |
| Database credentials       | Multiple engines, SSH reference, `creds run` argv/log safety, item rotation, passphrase change                            |
| Template deletion safety   | Ten-item archive/restore exactness and separate explicit purge                                                            |
| Corruption/tampering       | Nonce/ciphertext/ID/group/key swaps all fail closed with no output                                                        |
| Backup/recovery            | Clean-database known-v1 restore, independent supported slots, attachment/tombstone semantics; history/audit unsupported   |
| Cross-platform             | Installation and smoke tests on Windows x64, macOS x64/arm64, Linux x64/arm64                                             |
| Direct show/copy/update    | Complete masked view, clipboard clear, piping, ambiguity, Unicode, narrow terminal, no argv/history leak                  |
| Same key on two devices    | Invite hash/expiry/single use, independent token, local unwrap, rotation/confirmation, revocation, end-to-end canary scan |

Each scenario needs an automated test where practical and a recorded manual test
for OS integrations that cannot be faithfully virtualized. A simulated platform
does not justify a packaged-platform support claim.

## CI and release gates

Every change runs formatting, linting, strict type checking, unit tests, and
focused package tests. Security-sensitive or release pipelines additionally run:

- property/fuzz tests with bounded sustained duration;
- real-MongoDB integration and API zero-knowledge tests;
- plaintext-canary scanning;
- dependency audit, lockfile diff review, secret scanning, and static analysis;
- coverage thresholds emphasizing crypto/error branches rather than a global
  percentage alone;
- package allowlist and `npm pack --dry-run` inspection;
- SBOM generation and security-sensitive dependency inventory;
- reproducible-build comparison where practical;
- platform install/smoke/keychain/key-file/clipboard/TUI tests;
- backup restore drill and signed-artifact/checksum verification.

No release is complete while a critical security TODO, failing gate, unsupported
dependency advisory, unreviewed primitive/envelope change, canary match, or
unverified target artifact remains. Exact commands and results belong in the
status document once the workspace scripts actually exist.
