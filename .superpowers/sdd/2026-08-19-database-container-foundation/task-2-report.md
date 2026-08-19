# Task 2: Database-domain cryptography evidence

## Scope completed

- Added a branded 256-bit `DatabaseRootKey` and secure generator.
- Added database-only canonical AAD, detached XChaCha20-Poly1305 encryption,
  database owner/recovery slots, catalog helpers, and database-to-vault root
  wrapping.
- Exported the new API from `@kavrix/crypto` without modifying the existing
  vault AAD codec or its known-answer vectors.
- Did not add identities, grants, sharing, commands, storage, profiles, or
  migrations. `vitest.config.ts` did not require a change because its existing
  `packages/crypto/test/**/*.test.ts` include already discovers the new test.

## RED evidence

The test was added before the implementation. The initial focused test command:

```text
pnpm exec vitest run packages/crypto/test/database-crypto.test.ts
```

failed as expected with:

```text
FAIL  packages/crypto/test/database-crypto.test.ts
Error: Cannot find module '../src/database-crypto.js'
Test Files  1 failed (1)
Tests  no tests
```

This demonstrated the missing database-domain implementation before production
code was added.

## GREEN evidence

All commands below were run from
`/Users/radheykrishnaaa/Documents/GitHub/oss/kavrix/.worktrees/database-container-foundation`.

| Check                                                                                                                                                                     | Result                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| `pnpm exec vitest run packages/crypto/test/database-crypto.test.ts`                                                                                                       | Passed: 1 file, 13 tests   |
| `pnpm --filter @kavrix/crypto typecheck`                                                                                                                                  | Passed                     |
| `pnpm --filter @kavrix/crypto build`                                                                                                                                      | Passed                     |
| `pnpm --filter @kavrix/crypto test`                                                                                                                                       | Passed: 9 files, 101 tests |
| `pnpm exec eslint packages/crypto/src/database-crypto.ts packages/crypto/src/keys.ts packages/crypto/src/index.ts packages/crypto/test/database-crypto.test.ts`           | Passed with zero warnings  |
| `pnpm exec prettier --check packages/crypto/src/database-crypto.ts packages/crypto/src/keys.ts packages/crypto/src/index.ts packages/crypto/test/database-crypto.test.ts` | Passed                     |
| `git diff --check`                                                                                                                                                        | Passed                     |

The full crypto suite includes the existing AEAD known-answer-vector coverage;
all 35 AEAD tests and all 101 crypto tests passed unchanged.

## Security decisions

- Database AAD uses the separate `kavrix/database-aad/v1` domain. Every AAD
  field is length-prefixed, and optional `vaultId` uses an explicit
  present/absent marker.
- All database contexts and envelopes are parsed through Task 1 schemas.
  Database root, catalog, and wrapped-vault-root helper APIs additionally
  enforce their exact context relationships.
- Encryption calls libsodium detached XChaCha20-Poly1305-IETF directly,
  enforces 32-byte keys and existing ciphertext bounds, and stores a schema
  validated envelope.
- Decryption canonicalizes stored and expected AAD independently, compares
  them in constant time, maps every failure to `AuthenticationError`, and
  clears nonce, ciphertext, tag, and AAD scratch buffers in `finally`.
- Portable and recovery database slots use distinct HKDF-SHA-256 domains:
  `kavrix/database-root-wrap/v1` and
  `kavrix/database-recovery-wrap/v1`. Recovery slot creation generates a
  separate recovery key and clears it if creation does not complete.
- Runtime schema parsing prevents vault recovery slots and vault-only documents
  from being accepted as database recovery slots. The tests cover that boundary,
  AAD/context swaps, nonce/ciphertext/tag/key-version tampering, and a
  plaintext canary that is absent from serialized envelopes.

## Files changed

- `packages/crypto/src/database-crypto.ts`: database AAD, AEAD, DRK slots,
  catalog encryption, and vault-root wrapping APIs.
- `packages/crypto/src/keys.ts`: `DatabaseRootKey` branding and generator.
- `packages/crypto/src/index.ts`: database crypto exports.
- `packages/crypto/test/database-crypto.test.ts`: TDD misuse, tamper,
  relationship, slot-isolation, round-trip, and plaintext-canary coverage.

## Commit

Implementation commit SHA: `7d19e50` (the implementation commit before this
evidence-reference amendment).

## Wrong-key coverage follow-up

An independent review identified missing misuse coverage for distinct but valid
32-byte keys. No production change was needed: the existing implementation
already returned only `AuthenticationError` for these failure paths.

- Added a direct envelope-decryption test using a second generated database
  root key and asserting generic `AuthenticationError` equality.
- Added portable-slot and database-recovery-slot unlock tests using distinct
  generated valid keys and asserting generic `AuthenticationError` equality.
- The follow-up test secrets use `try`/`finally` cleanup and zeroize every
  generated portable, recovery, and database-root key on all terminal paths.

Follow-up verification:

| Check                                                               | Result                     |
| ------------------------------------------------------------------- | -------------------------- |
| `pnpm exec vitest run packages/crypto/test/database-crypto.test.ts` | Passed: 1 file, 15 tests   |
| `pnpm --filter @kavrix/crypto test`                                 | Passed: 9 files, 103 tests |
| changed-file ESLint and Prettier check                              | Passed with zero warnings  |
| `git diff --check`                                                  | Passed                     |
