# Template Publication Recovery Design

## Objective

Make template-migration publication recovery survive a crash after durable local
reconciliation without replaying an already accepted publication. Preserve the
existing fail-closed distinction between untrusted protocol failures and corrupt
or unavailable local state.

## Scope

This change covers the current outbound-observation work in `packages/sync`, its
client integration tests, and real-SQLite crash/reopen coverage in
`packages/local-store`. The pull, generic push, template publication, protected
rollback anchor, and durable receipt paths must remain consistent.

It does not compose missing public CLI vault commands, weaken validation, publish
a release, or claim that Kavrix is ready for real credentials.

## Selected Approach

Keep strict protocol validation and diagnose the mismatch at the owning boundary.
The template recovery fixture and engine must describe the same contiguous server
change range: the observation's replay start, accepted response sequences, staged
pull changes, and final cursor must agree exactly. If the fixture is inconsistent,
correct the fixture. If the engine omits a required accepted change or derives the
wrong replay boundary, correct the engine with the smallest focused change.

Do not translate `SyncProtocolError` into `SyncLocalStateError` merely to satisfy
the assertion. A protocol error must continue to identify malformed, incomplete,
or contradictory untrusted server data. A local-state error must continue to
represent failures while reading, reconciling, or publishing durable local state.

## Recovery Flow

1. Load and validate protected rollback state and local durable work.
2. Publish the template migration with its stable idempotency key.
3. Persist the authenticated outbound observation before trusting the response as
   durably reconciled.
4. Pull the exact contiguous change range required by the observation.
5. Validate response identity, accepted mutations, sequence continuity, byte
   bounds, records, and terminal cursor before local reconciliation.
6. Atomically reconcile the staged changes, cursor, queue completion, and durable
   completion receipt.
7. If the process fails after that transaction, reopening confirms the exact
   receipt from protected state and does not publish the template migration again.
8. Clear the protected observation only after confirmation, retaining enough
   durable evidence to release the completion pin safely.

## Security and Error Handling

- Never weaken schema, size, sequence, record-hash, vault, device, or idempotency
  validation.
- Fail closed on missing or duplicate changes, gaps, mismatched accepted records,
  stale cursors, corrupt receipts, or contradictory protected state.
- Do not log ciphertext contents, keys, tokens, passphrases, or decrypted values.
- Preserve atomic SQLite publication and crash-reopen semantics.
- Preserve network-free recovery when the exact durable receipt already exists.

## Verification

The implementation is complete only when:

- The focused real-SQLite template crash/reopen test passes and proves no replay.
- Generic outbound recovery tests remain green.
- The outbound reconciliation adversarial matrix remains green.
- Sync engine and client session regression suites pass.
- Formatting, linting, type checking, build, and the broad repository test suite
  are run; environment-specific or pre-existing failures are reported exactly.
- `docs/implementation-status.md` is updated only if current observable evidence
  changes, and must continue to state that the public vault lifecycle is missing.

## Delivery

The pull request branch includes the current local `main` history, which is 48
commits ahead of the locally recorded `origin/main`, plus the existing uncommitted
outbound-recovery work and this fix. The PR targets `main`. No tag, release, npm
publication, or production deployment is part of this change.
