# Threat model

## Assets

- database/vault labels and credential names, values, and encrypted payloads;
- database-owner key files, database recovery kits, and legacy protected files;
- database root keys, independent vault root keys, slot metadata, and recovery state;
- MongoDB connection credentials supplied at runtime.

## Intended protections

Kavrix derives and unwraps keys locally, authenticates every persisted envelope,
and sends MongoDB only an opaque database document and opaque vault documents.
Private database/vault labels and credential data remain encrypted. A DRK wraps
independent VRKs; database, vault, entity, purpose, version, revision, and digest
bindings prevent authenticated envelopes from being transplanted.

The MongoDB adapter requires transactions for database/catalog-plus-vault
publication and rejects remote connections without explicit validated TLS. It
rejects invalid-certificate, invalid-hostname, and explicit TLS-disablement options.

Protected files are passphrase-bound and permission checked. Secret input is
masked or framed through stdin; secrets are not accepted as positional command
arguments, logged, or written to settings files.

## Out of scope

A fully privileged or same-user process running after unlock can inspect process
memory, keylog input, capture screen/terminal/clipboard output, or copy plaintext.
JavaScript cannot guarantee erasure of every secret copy. MongoDB and local-file
observers can see opaque IDs, revisions, timestamps, sizes, routing relationships,
and access timing. A datastore operator can deny service, delete data, or retain
historical snapshots. Losing every authorized owner key and database recovery kit
is intentionally unrecoverable.

The design uses versioned XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, and SHA-256
through reviewed libraries. It does not claim encryption is permanently
unbreakable or protect against future cryptanalytic advances without migration.

## Rollback protection

Database and vault envelopes authenticate their metadata and exact revision.
After unlock, Kavrix maintains a restrictive DRK-authenticated local anchor with
the database/catalog head and authenticated vault-head set. A datastore-only
administrator who presents a lower revision, same-revision fork, missing expected
vault, or invalid reappearance is rejected before credentials are exposed.
Ordinary owner-key opens require an exact anchor match, including against an
authenticated newer datastore state; stale writers fail their expected-revision
publication rather than overwrite another writer. Only the recovery workflow may
forward-reconcile its authenticated companion anchor after an owner mutation.

Database recovery requires the matching recovery kit, database snapshot, and
trusted anchor. Deleting or corrupting the anchor fails closed and is a manual
recovery condition. Recovery does not erase old ciphertext snapshots.

## Execution and authorization boundaries

`kavrix run`, stored policies, temporary grants, and the agent firewall add a
scoped-execution layer on top of the vault. Its guarantees are process hygiene
and authorization, not a sandbox.

What this layer genuinely provides:

- Secrets reach only the addressed child's environment — never argv (the
  runner rejects mapped secret values appearing in the executable or argument
  list before spawn), never files, never the parent environment, never logs or
  audit records.
- Only explicitly requested credentials are decrypted; an unknown name fails
  closed with `CREDENTIAL_MISSING` before any child exists.
- Commands are spawned through fixed executable paths with `shell: false` and
  argument arrays; shell wrappers cannot interpose between Kavrix and spawn.
- Stored policies bind credentials to command allowlists, optional SHA-256
  executable pins, execution-window TTLs, use counts, reveal permission, and
  confirmation requirements; deny entries block every path including plain
  runs and reveals. Evaluation happens before spawn and fails closed.
- Grants are consumable authorizations sealed in the same AEAD state as
  policies; expiry, exhaustion, and revocation are re-checked inside a locked
  transition at consumption time, so two concurrent invocations can never both
  claim the final use. Revoked/expired/exhausted/unknown references map to
  distinct stable exit codes.
- The authorization sidecar is encrypted under a key derived from the database
  root key (HKDF-SHA-256) and authenticated against scope identity plus a
  monotonic sequence: forgery, corruption, cross-database transplant, and any
  byte-level tampering or reformatting fail closed as integrity failures.
- Agent firewall sessions hand the agent a local broker endpoint and per-run
  token but no credential material; each requested operation is authorized
  against configured permissions, and the secret is injected directly into the
  authorized child only. Token comparison is constant-time; denial always ends
  with an explicit exit frame so denials are distinguishable from breakage.

What this layer explicitly cannot do:

- The authorized program can read its own environment by design and may print,
  transform, or exfiltrate it. Same-user malware can inspect child memory,
  platform process APIs where available (`/proc/<pid>/environ` subject to
  kernel restrictions), attach debuggers where permitted, read crash dumps, or
  capture swap. JavaScript cannot guarantee zeroization of injected strings or
  buffers after child exit.
- Default `run` mode hands the terminal to the child unfiltered; captured
  `--json` mode redacts exact injected byte sequences from bounded output
  (a child exceeding the per-stream bound is killed by an output-limit
  termination) but cannot redact encodings or transformations of them.
- Executable pinning narrows, but does not close, the resolve-to-spawn window:
  a same-user attacker who replaces the file between hashing and spawn wins
  that race. Portable open-then-execute of one descriptor is not available.
- Termination reaches only the direct child; descendants it already forked
  survive timeouts and aborts. Windows additionally copies a fixed set of
  system variables into every child regardless of the supplied environment;
  none of them carry released values.
- Windows command scripts (.bat/.cmd/.com) are refused outright because
  launching them requires cmd.exe argument re-parsing; users must invoke real
  executables. This is fail-closed refusal, not protection.
- Policy/grant state is authenticated against forgery and corruption, not
  against a disk-level same-user attacker who restores older authentic sidecar
  bytes; the monotonic sequence makes such rollback visible to audit review
  and its effect is bounded by whatever TTLs and use counts were previously
  recorded. Wall-clock checks reject regression before creation time, but a
  same-user forward clock change is undetectable locally.
- Lock contention over the authorization state fails closed rather than
  blocking indefinitely; concurrent modification is serialized by the
  protected-file lock.

## Sharing boundary

Local-file sharing means running `kavrix db key create` and sharing the resulting
fresh share key with its exact matching encrypted database snapshot. Deliver the
passphrase separately; the one-use authenticated bootstrap creates the
recipient's anchor on first open. Do not copy the primary owner key. Once
unlocked, the shared pair grants access to all vaults, and Kavrix cannot revoke a
copied local key or snapshot. Fine-grained identities, recipient discovery,
signed grants, reader/editor/owner roles, revocation through VRK rotation, and
ownership transfer are future work and provide no current protection.

## Release evidence

The release gate includes schema/crypto tamper tests, protected-file tests,
Mongo URI policy tests, native Windows ACL/masked-terminal tests, packed-package
database-container acceptance on Windows/macOS/Linux, and a live MongoDB
integration test only when `KAVRIX_MONGODB_URI` names a disposable transaction-
capable topology. The repository does not claim live MongoDB proof when that URI
is absent.

The execution layer adds end-to-end suites (through the real CLI composition)
covering environment-only injection with digest canaries and argv absence,
exit-code/signal propagation, deny/reveal/confirmation/hash-pin/TTL policy
paths, grant expiry/exhaustion/revocation, sealed-state tamper and reformat
rejection, audit content without plaintext, and a live agent-broker session
exercising allow, unknown-permission, deny-entry, confirmation-unavailable,
unresolved-executable, missing-injection-mapping, oversized-output framing,
and exit-code propagation. Windows-specific refusal semantics are asserted
through injected platform parameters; POSIX process-group signal behavior is
covered only where the platform provides it.
