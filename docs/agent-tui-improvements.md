# Agent and TUI improvements in 0.2.41

The live workspace retains its existing schemas, core, crypto, storage, key-files,
runner, TUI, and CLI boundaries. This change improves the CLI-owned session host
and broker; it adds no hosted service and changes no encrypted data format.

## Current behavior

| Area                 | Implementation                                                                                               | Evidence                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Browse               | One bounded hierarchy snapshot; native database TUI uses zero subprocesses                                   | Command-count, metadata-canary, bounds, and real CLI journey tests                                |
| Policy/Grant/Audit   | One authenticated sealed-state snapshot; failures surface together                                           | Canonical schema validation, TUI command-count, and existing authorization read-only tests        |
| Common TUI actions   | One unlock across CRUD, Browse, copy/reveal, and authorization refresh; storage leases close between actions | Real file session tests prove one unlock, external writes, released locks, and encrypted canaries |
| Session lifetime     | Two idle minutes or fifteen minutes since unlock; failures, profile changes, and exit dispose it             | Idle/absolute expiry, key/storage tampering, disposal, and router draft-clearing tests            |
| Broker execution     | Four execution slots, 32 queued requests, ten-second admission wait                                          | Fast request completes while another child waits; single-slot queue timeout and overload tests    |
| Broker I/O and audit | Independent sockets, concurrent stdout/stderr drain, serialized confirmations and sealed audit writes        | Large stderr, output isolation, completion audit, and protocol tests                              |
| Startup and dry-run  | No mandatory splash delay; Agent dry-run receives no unlock inputs                                           | Mounted splash and backend frame tests                                                            |

Reuse does not cache decrypted credentials or skip integrity validation. Each
operation reads the protected key file, authenticates current database/vault
state, and checks the rollback anchor. Large vault authentication and MongoDB
connection establishment remain real costs. Administrative subprocesses invalidate
reusable keys before running; the next common action unlocks afresh. Legacy
standalone profiles retain their established command route and TUI lifetime limits.
Navigation alone does not renew the idle deadline. In-progress actions settle
before cleanup; a stopped or failed write must not be assumed rolled back.

Metadata remains private organizational information behind authenticated access.
Hierarchy responses omit values, notes, attachments, and history. Copy/reveal
continues to enforce reveal policy. Key buffers are cleared on disposal; JavaScript
cannot guarantee erasure of runtime string copies or protection from an already
compromised unlocked host.

## Next candidates

1. Add disposable-vault median/p95 benchmarks for real TUI actions, with safe
   action labels and subprocess counts. Separate Windows/file evidence from real
   MongoDB and macOS/Linux results; do not include protected input or output values.
2. Add an agent permission inspector using canonical configuration schemas and
   the existing policy engine, including executable pins and denial explanations.
3. Add an owner-authorized broker status port for active requests, queue depth,
   elapsed time, and terminal outcomes, containing metadata only.
4. Add lazy hierarchy expansion/search beyond the bounded preview and explicit
   cancellation for read operations. Reconcile authenticated state after an
   interrupted mutation before claiming rollback or allowing further writes.

These candidates are proposals, not shipped commands. The Agent TUI screen still
performs project configuration dry-run; it is not a live broker dashboard.

## Verification boundary

The 0.2.41 local Windows run passed 2,069 tests with 21 environment-gated tests
skipped. Coverage passed unchanged thresholds: 86.66% statements, 80.23%
branches, 91.03% functions, and 88.22% lines. Build, formatting, lint, and type
checks also passed, as did packed-package smoke, every-command local-file
acceptance, database-container acceptance, package-content dry-run, and dependency
audit (no known vulnerabilities). Skipped integration tests do not establish live
transactional MongoDB behavior.

Focused native Windows tests cover the implementation invariants above. Full
local release preflight, cross-platform CI, exact-commit CodeQL, trusted npm
publication, registry-integrity reconciliation, and GitHub release verification
are required before publication is claimed. See [release notes](release-notes-0.2.41.md)
and the [canonical release procedure](release.md). Operation counts are proven by
tests; no measured end-to-end latency improvement is claimed.

## 0.2.41 release checkpoint

The release tag `v0.2.41` points to
`c60aa21b39eda15943664688356732dba222451c`. Its [21 CI jobs](https://github.com/d4rkNinja/kavrix/actions/runs/37542798208)
and [CodeQL analysis](https://github.com/d4rkNinja/kavrix/actions/runs/37542798145)
passed. The [publishing run](https://github.com/d4rkNinja/kavrix/actions/runs/37545556440)
validated the archive and npm accepted the first upload with signed provenance.

On 2026-10-07, npm made 0.2.41 public. The failed-jobs retry reconciled the
original archive against registry integrity and completed successfully, including
[GitHub release creation](https://github.com/d4rkNinja/kavrix/releases/tag/v0.2.41).
The npm `latest` tag was verified as 0.2.41 at that checkpoint, with signed
provenance. No release tag moved and no CI gate was bypassed. The earlier staged
delay is covered by the [processing/staged-version procedure](release.md#processing-and-staged-versions).

The retained archive's SHA-256 is
`b30bf2bb688f8d67b9976b75b76451fff0d4c69f0094e95edd229b949c4e735b`;
its expected npm integrity is
`sha512-bRDgH8fARRLfbcLepJNOCxa8ywpJ2Ja1K7w+y9TPWPtMqdbwbawROM2AMyygnhhVMR5LYkYMj6P/MrdShFxu2Q==`.
