# Local-first multi-device and team database design

**Status:** Approved product design; implementation in progress

**Date:** 2026-08-31

**Scope:** Local single-device databases and self-hosted MongoDB databases used by one principal on multiple devices or by a team

## Purpose

Kavrix must provide one coherent product for solo and team developers without
weakening its zero-knowledge boundary. A user chooses the storage mode per
database:

- **local** keeps an encrypted database file on one device and requires no
  network service;
- **online** uses a self-hosted, transaction-capable MongoDB deployment plus an
  encrypted local replica on each enrolled device.

An online database may have one principal with several devices or several
principals with several devices. The user-facing sharing boundary is the whole
database: a member's role applies to every current and future vault in that
database. The Database Root Key (DRK) is never distributed as a membership key.
Database recovery authority remains separate from ordinary membership.

The first public online/team release is gated as one production feature. Its
internal delivery is incremental, but partial collaboration commands remain
hidden until the complete release matrix passes.

## Success criteria

A release candidate is successful only when all of these journeys are observable
through the packed CLI and the interactive TUI where applicable:

1. a new local user completes profile, database, vault, and verified recovery
   setup without copying opaque identifiers between commands;
2. a solo developer converts or creates an online database, enrolls a second
   device through an out-of-band bundle, works offline, reconnects, and observes
   exactly-once synchronization;
3. an owner invites a principal as reader or editor, the recipient validates the
   out-of-band trust anchor, and both devices converge without plaintext reaching
   MongoDB;
4. concurrent changes to different records merge, while conflicting changes to
   the same logical object stop for explicit resolution;
5. revoking a principal or device immediately rejects its new signatures and
   completes resumable rekeying before affected vaults accept further writes;
6. an encrypted backup is created, verified, restored copy-first into a new
   destination, reopened, and compared against the complete authenticated source;
7. a lost active key is replaced from a portable recovery bundle on a fresh
   machine without weakening rollback checks;
8. every supported failure is sanitized, bounded, retry-safe, and represented by
   a stable CLI/JSON result.

## Non-goals for the first public release

- Kavrix-hosted infrastructure, accounts, email delivery, billing, or a public
  identity directory;
- a web application;
- local-file collaboration or member-level access control for local databases;
- sharing individual vaults, items, or fields independently of database
  membership;
- automatic conflict resolution for competing writes to the same logical object;
- retroactive erasure of secrets or old keys already copied by an authorized
  member;
- attachment transfer, history restoration, or attachment mutation commands;
- a continuously running sync daemon required for correctness.

## Considered approaches

### 1. Incremental activation of the existing client stack — selected

Promote the parked client, local-store, sync, keychain, clipboard, and
import-export packages only as their production journeys become composed and
verified. Preserve the existing collaboration protocol as the per-vault
cryptographic enforcement layer, and add a bounded database-membership
orchestrator above it.

This approach reuses the existing rollback, idempotency, enrollment, mutation,
and recovery foundations while keeping every release gate explicit. It has the
smallest new trust boundary and permits vertical-slice verification.

### 2. Publish the parked stack as one release — rejected

Activating all parked packages at once would expose contracts that currently have
focused tests but are not part of the supported workspace, packed executable, or
cross-platform acceptance boundary. It would make failures difficult to localize
and create unsupported public APIs before the user journeys are complete.

### 3. Add a Kavrix API or hosted control plane — rejected

A new service could provide account discovery and central coordination, but it
would add authentication, authorization, operations, metadata, deployment, and
availability boundaries that are unnecessary for self-hosted MongoDB. The first
online release remains direct-to-MongoDB and zero-knowledge.

## Product concepts

### Database profile

A protected, non-secret profile selects `local` or `online` mode and its routing
metadata. It never stores a MongoDB URI, passphrase, recovery secret, portable
key, device secret, DRK, or VRK. The selected profile and a safe default database
and vault selection are loaded automatically after onboarding.

### Principal and device

A principal owns a protected Ed25519 root signing identity. A principal may
certify several devices. Each device has independent Ed25519 signing and X25519
encryption keys, its own protected rollback anchor, and a stable opaque device
identifier. Device keys are never copied between devices.

Roles bind to principals. VRK envelopes bind to individual active devices. A
device can be listed and revoked without removing its principal's other devices.

### Database membership

Online databases have one canonical authenticated database-membership state with
a monotonic generation and digest. It contains bounded opaque principal/device
membership, role, lifecycle, approval-policy, and denial information. Human
labels remain inside client-encrypted metadata.

The user-facing roles are:

- **reader:** decrypt and use credentials subject to local reveal, execution,
  confirmation, and field policies; cannot publish content or administration;
- **editor:** reader permissions plus ordinary content mutations;
- **owner:** editor permissions plus invitations, membership, device, role,
  approval, recovery, and destruction workflows.

There must always be at least one active owner. Membership never grants the DRK
or database recovery authority.

### Vault enforcement

Every collaborative vault remains protected by an independent VRK and the
existing signed per-vault transition protocol. A collaborative vault references
the exact database-membership generation and digest from which its device
envelopes and role projection were derived.

Creating a vault in an online database generates envelopes for every active
member device. Adding a member or device is not considered active until all
current vaults contain its exact role projection and VRK envelope. Removing a
member or device first advances the database denial fence so new signatures fail
immediately, then rotates every affected VRK through a resumable bounded journal.
Affected vaults remain `rekey-required` and reject writes until their rotation
commits. Unaffected reads may continue only when their protected anchors and
membership tuple validate.

Database-wide administration is therefore a journaled workflow, not one
unbounded MongoDB transaction. Each per-vault transition is individually atomic,
idempotent by operation ID, and recoverable after response loss. The database
workflow commits terminal success only after every vault reaches the exact
target membership generation. Permanent signed tombstones prevent a completed
removal from being replayed as enrollment.

## Storage and synchronization

### Local mode

Local mode continues to use the protected encrypted database container and
revision anchor. It has no identity directory, membership state, local replica,
or network requirement. A user can later perform an explicit copy-first
conversion into a new online database; conversion never mutates the local source.

### Online mode

MongoDB remains an untrusted opaque store. It receives bounded routing metadata,
ciphertext, wrapped keys, signatures, revisions, digests, and operation outcomes,
but no plaintext labels or values, passphrases, DRKs, VRKs, recovery material, or
device private keys.

Each enrolled device keeps an encrypted local SQLite replica containing opaque
records, durable outbound operations, conflict records, synchronization pins,
lifecycle journals, and protected rollback state. The replica is not a plaintext
cache. One device-local writer lease serializes mutations.

An online command follows this sequence:

1. authenticate the profile, device, protected anchor, and local replica;
2. when reachable, pull and verify remote changes before releasing plaintext;
3. execute the requested read or local mutation against an authenticated state;
4. persist an outbound mutation and its idempotency key before reporting local
   acceptance;
5. when reachable, publish immutable candidate bytes and reconcile the signed
   outcome;
6. persist the accepted head and anchor before reporting synchronized success;
7. clear owned secret buffers and release the writer lease.

Network failure never discards or regenerates a queued operation. An ambiguous
publication retries the exact operation ID, request digest, and candidate bytes.
`kavrix sync` exposes a complete synchronization pass. Ordinary online commands
perform bounded pull-before/read and push-after-mutation attempts but do not need
a continuously running daemon.

### Conflicts

Mutations to independent logical records may merge only when their authenticated
predecessors and schema ownership prove independence. Competing changes to the
same context, service, item, field, membership object, policy, or parent/child
relationship create a durable redacted conflict. Kavrix never silently selects a
wall-clock winner.

`kavrix conflict list|show|resolve` and the TUI present sanitized metadata and
explicit choices. Resolution produces a new signed mutation from the current
authenticated head; it does not rewrite either historical operation. Membership,
revocation, recovery, ownership, and destruction conflicts always fail closed
for owner resolution and are never auto-merged.

## Enrollment and invitations

There is no central account service. A principal creates a protected local
identity and exports a bounded public identity bundle. Private keys and device
secrets never enter the bundle.

The online workflow is:

1. the recipient transfers a public identity/device bundle out of band;
2. an owner verifies its human-readable fingerprint and creates a short-lived,
   single-recipient invitation for reader or editor;
3. the owner-side workflow prepares every required per-vault envelope and signs
   an enrollment receipt bound to the exact database authority, membership
   generation, role, recipient device, checkpoint, and expiry;
4. the recipient receives the invitation and signed first-use receipt out of
   band, validates the expected fingerprint, and opens only the matching
   discovery envelope;
5. exact-head or complete proof-chain validation succeeds before any plaintext
   is released; missing proof or expired material requires a fresh invitation;
6. acceptance becomes terminal only after every current vault and the local
   rollback anchor are verified.

Invite files/codes are path-safe, bounded, versioned, authenticated, one-time,
and sanitized when inspected. They contain no plaintext vault/database labels,
role directory, passphrase, recovery key, DRK, VRK, or device private key.

## Recovery and backups

### Recovery-readiness gate

Local onboarding strongly warns until a recovery path is created. Online mode,
device enrollment, and team invitations remain disabled until at least one
database recovery bundle has been created and verified against the current
database on a separate path.

A portable recovery bundle is one versioned protected artifact containing the
existing database recovery file and its required authenticated companion anchor
plus a bounded manifest. Creation writes a restrictive sibling temporary file,
fsyncs, atomically publishes, reopens, and verifies it. Import never trusts a
manifest without authenticating both embedded artifacts and their exact database
binding.

Database-authority recovery appoints at least one active owner, advances the
protected authority anchor, rotates affected VRKs, and leaves no ownerless state.
It does not erase old snapshots or revoke already copied plaintext.

### Encrypted database backups

The supported surface is `kavrix backup create|verify|restore`. A backup is a
bounded, versioned, authenticated encrypted stream covering the complete
database catalog, vault graph, collaboration state, required operation
outcomes/tombstones, and integrity metadata. Recovery material is not silently
embedded; the user stores the recovery bundle separately.

Restore is copy-first. It writes only to a new explicit destination, verifies the
entire graph and source digest before publication, establishes a fresh local
anchor, reopens the destination, and compares the canonical authenticated state.
Overwrite and merge restore are excluded from the first release. Local-file and
MongoDB sources and destinations use the same semantic verification contract.

Backup commands are safe for external schedulers through exact stdin frames and
stable JSON results. Kavrix does not require or ship a scheduling daemon.

## Unlocking and native key storage

Protected key files and masked passphrases remain the default on every platform.
Native keychain use is opt-in per device and has no plaintext-file fallback.

For configurable cross-command unlock periods, `kavrix unlock --ttl <duration>`
starts a minimal user-local session broker over a restrictive Unix socket or
Windows named pipe. The broker holds unwrapped device material only in owned
memory, authenticates every request with a per-session token, never returns raw
keys, and exits on TTL, explicit `kavrix lock`, terminal/session loss where
observable, or fatal integrity failure. Native keychain storage may protect the
device bootstrap secret, subject to platform user-presence support; it does not
replace the broker's TTL. Correctness never depends on the broker, and commands
can always fall back to masked prompting.

## Administrative approvals

One active owner may invite readers/editors, revoke a device, or remove a
reader/editor. Adding an owner, transferring ownership, removing an owner,
changing approval policy, or destroying an online database uses the exact signed
approval/transfer protocol.

When at least two eligible owners exist, those sensitive operations require one
additional distinct owner. With only one owner, adding a second owner requires
explicit recovery-readiness verification and recipient acceptance; removing the
last owner remains impossible. Database-authority recovery is the only supported
successor path after all ordinary owners are unavailable.

Database destruction requires an authenticated complete deletion plan, fresh
challenge, exact database identity, verified backup/recovery disclosure, terminal
tombstone publication, and the required owner quorum. There is no `--force` or
`--yes` bypass.

## CLI and TUI composition

The CLI remains authoritative and fully scriptable. Every interactive journey
has schema-derived command descriptors, exact stdin frames, `--json` output,
stable exit codes, redaction, and no secret arguments.

The TUI composes the same use cases for:

- first-run profile/database/vault/recovery setup;
- identity creation and device listing;
- invitation creation, inspection, and acceptance;
- member/role/device administration;
- synchronization and conflict resolution;
- backup creation, verification, and restore planning.

The TUI owns presentation and emits typed intents. It never owns persistence,
cryptography, transport, or authorization decisions. Non-interactive execution
never imports Ink or emits ANSI.

## Error handling and observability

All trust-boundary failures are fail-closed and sanitized. Authentication errors
do not reveal which secret component was close. Remote unavailability,
authorization denial, conflict, rekey-required state, expired invitation,
approval required, recovery-readiness failure, corruption, and ambiguous
publication have distinct stable machine outcomes.

Security events append bounded metadata to the authenticated audit state. Team
events identify only opaque database/principal/device/operation references and
never contain human labels, MongoDB URIs, file paths outside an explicitly
requested local diagnostic, secret values, private keys, or recovery material.

Operational status reports local/remote heads, queue depth, conflict count,
membership generation, rekey progress, last verified backup time, and recovery
readiness without decrypting credential values.

## Compatibility and migration

Local database format remains readable by the existing supported CLI. Conversion
to online/team mode is explicit, copy-first, journaled, and one-way for the new
destination. The local source is unchanged.

Collaborative vault documents retain a strict format that older clients reject.
Mixed-client tests prove that legacy predicates cannot update, delete, or
downgrade collaborative rows. Every new schema and wire contract is versioned and
strict; unknown versions and fields fail closed.

Activation proceeds package by package. A parked package becomes an active
workspace/release dependency only when its public contracts, dependency graph,
package contents, platform behavior, and complete owning journey pass the active
release gates. Documentation describes a feature as shipped only after the packed
CLI evidence exists.

## Implementation boundaries

- `packages/schemas`: canonical identity, device, database membership, invite,
  recovery-bundle, backup, sync-status, conflict, and CLI result schemas.
- `packages/core`: role, membership, approval, readiness, conflict, and lifecycle
  policies plus framework-free ports/use cases.
- `packages/crypto`: existing reviewed identity, signature, sealed-box, hierarchy,
  envelope, and collaboration primitives; no CLI or persistence imports.
- `packages/key-files`: protected identities, device keys, anchors, recovery
  bundles, workflow journals, and session-token files.
- `packages/storage`: opaque MongoDB/local-container transactions, collaboration
  rows, operation outcomes, tombstones, and bounded range reads.
- `packages/local-store`: encrypted local replica, queues, conflicts, pins, and
  writer leases.
- `packages/sync`: deterministic opaque synchronization and recovery.
- `packages/client`: unlocked orchestration, database-wide workflow journals,
  enrollment, rekey, sync, backup, and recovery composition.
- `packages/keychain`: optional native device bootstrap storage.
- `packages/import-export`: bounded streaming recovery-bundle and backup formats.
- `packages/tui`: schema-driven presentation and typed intents.
- `apps/cli`: command parsing, protected input, orchestration wiring, sanitized
  output, and stable process semantics.

Dependency direction continues inward. No storage, CLI, TUI, MongoDB, or native
adapter enters core or crypto.

## Verification and release gate

The public online/team surface remains hidden until all applicable checks pass:

- schema bounds, malformed input, unknown versions, duplicate identities, and
  cross-database/context-swap tests;
- crypto tampering, signature-domain swap, envelope-recipient swap, key-epoch,
  plaintext/key canaries, and owned-buffer cleanup tests;
- local writer, multi-process, MongoDB transaction, response-loss, idempotency,
  retry, ordering, fork, rollback, and interruption tests;
- offline mutation, reconnect, independent merge, same-object conflict, conflict
  resolution, queue durability, and anchor persistence tests;
- enrollment first-use, receipt expiry, proof withholding, device addition,
  device/principal revocation, rekey resume, approval replay, transfer, last-owner,
  authority recovery, and destruction tests;
- backup interruption, truncation, tampering, wrong-context, fresh-machine,
  local-to-local, Mongo-to-local, local-to-Mongo, and Mongo-to-Mongo restore tests;
- protected-file symlink, hard-link, replacement-race, ACL/mode, oversized-input,
  and cleanup tests;
- masked input, exact stdin frames, ANSI/OSC sanitization, JSON redaction, stable
  exit codes, packed-package, and fresh-home end-to-end tests;
- Windows, macOS, and Linux native evidence for key files, keychain, terminal,
  sockets/pipes, SQLite, and process termination;
- a real disposable transaction-capable MongoDB replica-set matrix with TLS
  policy, concurrency, canary, restore, and collaboration acceptance;
- format, lint, typecheck, build, unit/integration, coverage, dependency audit,
  package allowlist, SBOM/provenance, CI, and CodeQL gates on the exact candidate.

No production-ready or shipped claim is made until this matrix is complete and
the factual implementation ledger is reconciled with observable evidence.

## Delivery sequence

1. reconcile stale roadmap documentation and define active contract boundaries;
2. compose guided onboarding and recovery readiness on the supported local path;
3. activate and verify portable recovery bundles and encrypted backup/restore;
4. activate the encrypted local replica and deterministic sync for one principal
   with multiple devices;
5. add database membership, roles, invitation bundles, and device lifecycle;
6. compose resumable database-wide enrollment, revocation, and rekey workflows;
7. add conflict UI, owner approvals, transfer, authority recovery, and destruction;
8. add the optional unlock broker and native keychain integration;
9. complete TUI composition, packed acceptance, cross-platform evidence, and
   documentation reconciliation;
10. expose the public online/team commands only after the full release gate.
