# `@kavrix/local-store`

Durable local synchronization state for Node 24.19 using the built-in
`node:sqlite` adapter. The store implements the canonical
`SyncLocalStorePort` and persists only schema-validated opaque encrypted
records, public synchronization metadata, cursors, pending mutations, active
push batches, and bounded completion receipts.

The same adapter implements the canonical active-vault read, mutation-state,
generic mutation-queue, and atomic template-migration publication ports. Reads
overlay durable pending writes over pulled base records. A queued delete keeps
its exact active predecessor in a hidden bounded table and synthesizes the
canonical encrypted tombstone state immediately, so an offline restore remains
possible before or after reopen. Accepted pushes promote their exact records
and deletion state before pending rows are removed, preventing the UI from
temporarily reverting to older pulled state. `close()` checkpoints and closes
the connection; operations fail closed after closure.

`openSqliteVaultProfileStore` persists canonical, non-secret vault/device
profiles in a separate restrictive SQLite database. Exact retries are
idempotent; conflicting vault/device identities or protected locator reuse fail
closed. The store has no initialization-time delete because a remote bootstrap
may already have committed the identity. Profile rows and aggregate serialized
bytes are bounded and every load returns a freshly parsed structural copy. Each
canonical locator embeds the same vault/device identity as its profile, so
cross-identity locator reuse is rejected before insertion; independent unique
constraints remain as persistence-boundary defense in depth.

`SqliteInitializationJournal` implements the canonical v2 initialization journal
with exact encrypted/public records and active/committed profiles,
compare-and-set lifecycle transitions, operation and protected-locator
reservations, and atomic replacement by the non-secret bootstrap receipt.
`SqliteJoinLifecycleJournal` keeps only its operation/state/session-locator
mirror in SQLite. Its three 32-byte bearer values live exclusively in
`NativeJoinJournalSecrets`; no encoded protected record or bearer bytes are
written to SQLite.

Join recovery uses explicit `reserving`, `transitioning`, `deleting`, and
`committing` SQLite phases. Each intent is committed and checkpointed before
the native keychain mutation. Reopen reconciliation can therefore remove a
reservation that never reached the keychain, promote one that did, finish an
idempotent protected-state transition, repeat deletion, or finalize a receipt
after protected deletion. SQLite and the OS keychain are not claimed to be one
atomic store.

## Durability and security choices

- Pull-page application and cursor advancement share one `BEGIN IMMEDIATE`
  transaction. Mutation acknowledgement, base-record promotion, deletion of
  acknowledged pending rows, and active-batch completion are also atomic.
- A template migration is persisted and published as one canonical atomic
  request. Its response is bound to the exact request, ordered mutation
  identities/revisions, and canonical ciphertext hashes before all records are
  promoted together. Generic queue state and an atomic publication cannot
  coexist for the same vault; corruption that creates this state fails closed
  during open verification.
- Generic idempotency keys and template publication keys retain canonical
  completion receipts across reopen. Exact retry succeeds and changed reuse
  fails closed. Receipt tables are bounded by rows and aggregate bytes; oldest
  receipts are pruned transactionally while every just-completed key and the
  newest publication receipt are protected.
- `enqueueBatch` and atomic-publication enqueue report
  `OpaqueMutationDurabilityUnknownError` if the SQLite commit succeeded but a
  post-commit filesystem durability/security check failed. Callers can safely
  retry the same canonical request and must not silently re-key it.
- WAL mode, `synchronous=FULL`, full-fsync/checkpoint requests, foreign keys,
  `secure_delete`, a 5-second busy timeout, bounded WAL checkpoints, defensive
  mode, and `trusted_schema=OFF` are selected explicitly.
- The application ID, schema version, format marker, every normalized user
  table/index definition, SQLite integrity, canonical JSON, redundant row
  bindings, revisions, byte counts, and capacity limits are checked. Schema or
  data ambiguity is rejected generically.
- Limits are global to the database, not per vault. Defaults permit 128 vaults,
  100,000 records/256 MiB of record JSON, 10,000 pending mutations/64 MiB,
  100,000 generic completion receipts/64 MiB, 10,000 push-batch completion
  receipts/64 MiB, and 10,000 template completion receipts/64 MiB. Active
  records plus deletion predecessors share the record limits. Pending generic
  and template mutations share the pending limits. Completion tables prune
  their oldest receipt transactionally while retaining the just-completed
  receipt.
- The database has a configured 512 MiB page bound and each serialized row is
  bounded to 8 MiB by default. Pull pages are additionally bounded to 500 rows
  and 32 MiB.

On Unix, the immediate database directory must be owned by the current user
with mode `0700`; every database/WAL/SHM/journal leaf must be a regular,
single-link current-user file with mode `0600`. On Windows, Kavrix uses only
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with a fixed
minimal environment to create or verify protected current-user-only owner
DACLs on the directory and every SQLite leaf. Environment variables and
`PATH` never select the security tool. Symlinks, junctions, hardlinks,
unexpected file types, broad ACLs, and unverifiable ownership fail closed.

## Limitations

- SQLite is not database encryption. Opaque ciphertext and public identifiers,
  revisions, timestamps, and idempotency keys are visible to the local user.
- Bounded local completion receipts cannot permanently reserve every historical
  idempotency key. After an oldest receipt is pruned, protection against ancient
  changed-key reuse relies on the server's durable idempotency contract.
- The current sync format is `kavrix-local-sync-v2`; the profile-bearing
  initialization-journal format is v2. This package has no in-place migration
  from either earlier local format; an unsupported schema fails closed
  and must be rebuilt from the remote opaque vault after preserving any still
  pending local work through a separately reviewed migration flow.
- WAL, filesystem snapshots, SSD behavior, backups, and prior copies can retain
  superseded ciphertext despite `secure_delete` and best-effort cleanup.
- `DatabaseSync` performs synchronous SQLite work and can briefly block the
  Node event loop. WAL and the busy timeout coordinate multiple connections,
  but callers should still use one logical sync writer per vault.
- A crash after commit but before leaf-ACL tightening remains protected by the
  owner-only parent directory. A leftover leaf whose explicit ACL cannot be
  verified on reopen is rejected rather than repaired implicitly.
- Lifecycle journals hold an `O_EXCL` process-lifetime writer lease. Lease
  metadata is bounded canonical public data (`version`, PID, random nonce),
  never a secret. A live owner always blocks. Journal resume removes a dead
  owner only after current-user-only ACL/mode, regular/single-link type,
  canonical metadata, path/handle identity, repeated content, and repeated
  identity checks all pass; it then retries `O_EXCL`. Malformed, replaced, or
  linked leases fail closed. PID reuse intentionally blocks while the reused
  PID is live. `recoverStaleLocalWriterLease` exposes the same guarded recovery
  step to other local-writer compositions.
- Windows installed outside the fixed trusted `C:\Windows` root is unsupported.
  Network filesystems and filesystems without dependable ownership, link, ACL,
  locking, or full-fsync semantics are unsupported.
- Dead-owner detection uses the host process table and cannot distinguish a
  stale PID from a currently live reused PID; that ambiguity fails closed.
  Filesystems without reliable PID visibility, atomic exclusive create/unlink,
  stable file identity, or delete-while-open semantics are unsupported.
