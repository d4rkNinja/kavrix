# Team collaboration security protocol

**Status:** In progress; unavailable in the public CLI
**Date:** 2026-08-29
**Scope:** MongoDB-backed database vaults only

This document records the implementation boundary for the security-complete
team collaboration design. It supplements the product requirements supplied
for principal identities, device credentials, membership, revocation,
approvals, ownership transfer, rollback protection, and recovery.

No collaboration command may be registered and no collaborative vault may be
created by a released client until the complete release matrix in the target
design passes. Local-file databases remain whole-database artifacts and never
gain member-level access control.

## Assets, actors, and boundaries

Protected assets are principal root private keys, device signing and encryption
private keys, the current Vault Root Key (VRK), decrypted vault contents,
membership and approval state, enrollment trust, and each device's last
accepted state.

Actors are the database authority, vault owners, editors, readers, active and
revoked devices, the local Kavrix process, and an untrusted MongoDB operator.
The database authority retains recovery superauthority because possession of
the Database Root Key (DRK) can recover or replace vault ownership.

The security boundaries are:

- protected identity files and device-local rollback anchors;
- out-of-band public identities and enrollment receipts;
- the local unlocked process where keys and plaintext may exist;
- MongoDB, which receives only bounded public routing metadata, ciphertext,
  wrapped keys, digests, signatures, revisions, and operation outcomes; and
- terminal and error output, which never receives private keys, VRKs, plaintext
  credentials, enrollment secrets, or recovery material.

## Version and compatibility boundary

Collaborative vaults use a distinct strict document format. The existing
`databaseVaultDocumentSchema` remains unchanged. Consequently, an older client
rejects a collaborative document during parsing and its legacy revision-only
update predicate cannot match that document. A collaborative document is
structurally forbidden from containing the legacy `revision` field and uses
only `documentRevision`; storage tests exercise every legacy create, update,
and delete predicate, including a cached pre-migration writer, against a
collaborative document and require zero matches.

The first collaborative write is a one-way format transition for that vault.
Downgrading it to a legacy document is not supported. Migration must authenticate
the legacy vault, create one complete signed genesis state, publish it through
compare-and-swap, persist the local anchor, and be resumable by operation ID.

Genesis is not an ordinary member-authorized mutation. Its signed operation type
is `genesis-migration`; normal role authorization rejects that type. The dedicated
migration boundary requires document, membership, and policy revision 1, key
epoch 1, the authoritative registry generation and digest, one active initial
owner and certified device, and an immutable database-authority delegation plus
the initial owner's signed genesis transition. The authority delegation binds
the database and vault IDs, authority epoch and signing-key fingerprint, authority
recovery X25519 public key and fingerprint, genesis operation, tuple and head,
initial authorization-state digest, initial owner root and device fingerprints,
and issuance time. It is the reusable trust root for that vault; it is never
reissued to certify an ordinary revision. The genesis prior tuple is the
protocol-defined zero state (with key epoch 1 so no fictitious pre-collaboration
VRK exists), and its prior head is the domain-separated
`COLLABORATION_GENESIS_HEAD_DIGEST`, never an all-zero digest. The prior
authorization state, membership state, membership-history state, and empty
compacted-history prefix likewise use distinct domain-separated protocol
constants rather than caller-selected or all-zero digests. The encrypted history
begins with a signed `genesis-created` event. A revision-1 document that does not
satisfy every genesis invariant is rejected rather than routed through ordinary
transition validation.

## Cryptographic identities

A principal owns a protected Ed25519 root signing key. Each device has distinct
Ed25519 signing and X25519 encryption keys certified by that root. Roles bind to
principals; current VRK envelopes bind separately to every active device.

The database authority Ed25519 signing key and X25519 recovery key pair are
derived independently from the DRK with HKDF-SHA-256, unique versioned domains,
and the database ID. Their public keys and fingerprints are fixed by the
immutable genesis delegation. The recovery public key lets an active owner seal
each fresh VRK without possessing the DRK; only a DRK holder can derive the
private key and open that wrapper. This does not reduce the authority's existing
power: DRK compromise is already a root incident. An authority epoch cannot
repair DRK compromise by itself. In-place authority replacement requires a new
DRK, rewrapping every surviving VRK and catalog artifact, cross-certification
when the old authority is still trustworthy, and explicit out-of-band anchor
migration otherwise. Until that complete workflow is implemented and verified,
authority compromise requires migration to a new database.

All signatures cover canonical, domain-separated bytes. Device certificates,
public identity exports, authority delegations, enrollment receipts, approval
requests, transfer intents, authorization transitions, discovery envelopes,
mutation links, outcomes, and tombstones use different protocol domains. X25519
sealed boxes wrap only a 32-byte VRK for a member device or the authority
recovery public key; authorization comes from the authenticated authorization
chain, not from successful decryption alone.

The out-of-band enrollment receipt is the first-use trust anchor. An active
owner signs it, and it binds the immutable authority-delegation digest, issuer
root and device certificate, recipient identity and device certificate,
discovery and sealed-envelope digests, exact revision tuple and head,
authorization-state digest, an exact authenticated checkpoint, role, issuance,
and expiry. A key read only from the same untrusted MongoDB record is never
accepted as its own trust anchor. Exact-head first use succeeds directly. A
newer candidate must carry or make retrievable a complete signed proof from the
receipt checkpoint to the candidate head; missing, reordered, or invalid proof
fails closed and requires a fresh out-of-band receipt.

## State and publication

Every accepted collaborative state has one exact tuple:

- database-authority epoch;
- database device-status generation and signed registry digest;
- document revision and digest;
- membership revision and digest;
- policy revision and digest;
- key epoch;
- previous head digest and current head digest.

Every state also carries an `authorizationStateDigest` over the canonical
membership, root-certified device state, policy, and complete member and
authority-recovery key-envelope core. It excludes history, signatures and
certifications, its own digest field, document revision, and current head. This
projection is the only state used for role and policy authorization.
The first protocol version's complete authorization-relevant policy core is
the `approvalPolicy`; its scope, revision, authority and registry fence are
already explicit fields of the same authorization core, while policy signer and
timestamp metadata remain bound by the separately authenticated policy digest.

The encrypted membership manifest binds the exact prior head and complete next
revision tuple, but never the resulting new head. This avoids a commitment cycle:
the payload, manifest, discovery, and policy digests are computed first; the
outer mutation commitment then binds those digests, the prior head, operation ID
and type, actor principal and device, timestamp, prior and next authorization
state digests, and an optional authorization-transition digest; finally the new
head is computed. A `finalizedMutationLink` contains that complete commitment,
the derived resulting head, and the writer-device signature. For an ordinary
write the two authorization-state digests are identical and no transition is
present. For an administrative mutation, an active owner device signs a
separate transition binding the operation and type, prior head, prior and next
authorization-state digests and security revisions, the exact approval or
transfer evidence digest, and finite issuance and expiry. The signer is checked
against the authenticated prior state and prior policy. Changing any bound value
invalidates the signature and head.

The authority delegation is immutable and authority signatures are not required
for ordinary or owner-authorized mutations. Likewise, current owners do not all
co-sign each revision. Owner succession is established by the authenticated
transition chain beginning at the authority-delegated genesis state.

AEAD context and ciphertext digests are intentionally separate and acyclic. An
envelope's `metadataDigest` is the domain-separated digest of every other AAD
field. The payload or manifest digest is computed over the completed canonical
encrypted envelope, including that AAD, nonce, ciphertext, and authentication
tag. An encrypted-envelope digest must never be copied into its own AAD.

MongoDB publication compares database ID, vault ID, prior head, authority epoch,
the referenced database device-status generation and registry digest, all three
revisions, key epoch, and prior authorization-state digest. A database-authority
signed registry is an exceptional global deny and recovery fence: it can reject
globally compromised devices or authority epochs, but it is not a positive
allowlist that must be rewritten for routine principal-device enrollment.
Within one supported authority epoch its denial set is append-only: an update
cannot remove or rewrite a prior denial, and in-place authority replacement is
rejected until the separately documented DRK/anchor migration exists.
Normal device enrollment and revocation are root-certified and owner-authorized
inside the vault state. Rekey-required state is derived from a global deny event
and a vault's referenced generation; it does not require atomically marking an
unbounded set of vault documents.

A registry denial is prospective authorization evidence, not retroactive
signature erasure. A historical event or checkpoint signed by a then-valid
certified device remains authentic when its signed time precedes both the
certificate revocation boundary and the authority-signed denial time. The same
device is nevertheless rejected for current or later writes, transitions,
discovery, envelopes, enrollment issuance, and recipient access.

Every membership-history checkpoint names its signer principal and device.
Verification uses only that certified signing key and checks the checkpoint
time against membership creation/removal, device creation/revocation/expiry,
and the append-only registry denial time; trying every known key is forbidden.

One transaction replaces the complete collaborative vault, appends the exact
immutable finalized mutation link, and inserts a unique operation outcome whose
identity is database ID, vault ID, and operation ID. It records the canonical
request digest, operation and actor, prior and committed heads and tuples,
outcome digest, and a writer-device-signed mutation receipt. A repeated operation
with the same digest returns its recorded outcome; the same operation ID with a
different digest is corruption. Full outcome details and links remain for at
least the maximum protected local-journal, enrollment-receipt, and offline-retry
horizon. A compact immutable deduplication tombstone retains the writer-signed
receipt or its exact signed digest until vault destruction. MongoDB TTL cleanup
is never the logical expiry or deduplication boundary.

Mutation links are append-only and range-readable. Checkpoints may compact a
proof only when the checkpoint is itself reachable from an already protected
anchor or is explicitly pinned by an out-of-band enrollment receipt. Proof
withholding is an availability failure, not permission to skip validation.
Links alone are insufficient to validate later owner succession because a
verifier must establish which owner and policy were active before each
administrative change. Consequently every genesis or administrative proof entry
also persists a bounded encrypted authorization witness: the encrypted
membership manifest, recipient-scoped discovery records, exact tuple and
authorization-state digest, the exact authority-signed database-device registry
snapshot for that tuple, and the finalized-link digest. This makes each
intermediate registry generation independently verifiable without relying on a
mutable current registry. It never contains a historical plaintext membership
core or vault payload. An ordinary-write entry cannot carry a witness because
its authorization-state digest is unchanged.

The complete candidate state, VRK, nonces, ciphertext, timestamps, signatures,
request digest, and signed outcome are generated exactly once before entering a
MongoDB retryable transaction callback. The callback may only validate fencing
conditions and persist those immutable bytes. After an ambiguous response,
absence is actionable only after a successful authoritative outcome read; any
retry reuses the exact operation ID, request digest, and candidate bytes.

Discovery entries live inside the current vault document and, for administrative
history only, inside the corresponding encrypted authorization witness, so
membership, envelopes, and discovery changes cannot commit separately. They
bind the database/vault and authority epoch, authorization-state digest,
membership revision, key epoch, and the exact encrypted membership-manifest
digest—not each document head or delegation digest. Each current discovery
record names and is signed by the exact finalized-mutation writer. That writer
is an editor or owner authorized from the prior state (or the writer of an
authority-authenticated owner-recovery transition), so an ordinary editor write
never requires an undisclosed owner co-signature. The owner-signed enrollment
receipt separately binds the exact discovery-record digest for first-use trust.
The containing document or authorization witness binds the immutable delegation
outside the genesis head inputs, avoiding a commitment cycle. Therefore an editor can publish
an ordinary content write without obtaining a fresh owner signature. Queries use
database-scoped, domain-separated tags and return a bounded number of candidates.
One principal-scoped tag may intentionally select multiple device-specific
records for the same membership; uniqueness is enforced on tag, membership,
and recipient device together so every active device receives its own sealed
VRK without exposing a raw principal identifier.
No discovery entry contains an email, username, display label, organization,
vault label, plaintext role, or raw global fingerprint.

The scoped tag is pseudonymous, not secret: an operator who already knows a
candidate public identity and database ID may test likely membership. The vault
document has a serialized BSON budget materially below MongoDB's 16 MiB limit;
the payload, manifest, history, approvals, transfers, and discovery arrays each
have stricter component limits within that shared budget.

## Open and mutation rules

Before releasing plaintext, a device must parse all bounds, compare the remote
state to its protected anchor or receipt checkpoint, verify the immutable
authority delegation, validate every intervening mutation link and
authorization transition against its prior authenticated state and policy,
verify the signed discovery envelope, open the VRK into quarantined memory,
authenticate and validate the membership manifest and authorization-state
digest, verify its active device and role, authenticate the payload, and persist
the new anchor. Anchor persistence failure is a read failure. A skipped revision
is acceptable only with a complete valid proof chain; a bare newer head is not.

The anchor's `membershipDigest` is the domain-separated digest of the logical
membership and owner projection, not the full encrypted-manifest digest. The
full manifest necessarily changes when an ordinary write advances its
document/head-bound AAD while `membershipRevision` remains unchanged. The
logical digest remains stable for that write and changes for membership or
owner transitions; the full manifest digest is still verified independently.
Likewise, the anchor's `policyDigest` is the logical policy-revision and
approval-policy projection. The full signed policy artifact may be rebound to a
new registry generation without incrementing `policyRevision`; its complete
digest and signature are verified independently while the anchor tracks that
registry tuple in its dedicated fields.

The proof's starting authorization witness predates the first returned link, so
its writer identity is not recoverable from that proof object alone. For an
existing device it is used only as untrusted key transport until AEAD opening
produces a manifest whose logical membership-state digest and authorization-state
digest exactly match the protected anchor. During first-use enrollment the
owner-signed receipt instead pins the exact selected discovery-record digest.
Every later administrative witness and the current document is link-bound and
its discovery signatures are verified against that finalized-link writer.

Readers may decrypt but cannot create an accepted mutation. Editors may create
ordinary content mutations. Owners may perform administrative mutations subject
to the policy active before the action. Local reveal, clipboard, confirmation,
and execution policies remain independent and are never bypassed by team roles.

The confidentiality claim is therefore: only active member devices or the
database authority can unwrap or recover the current VRK. The authority is an
explicit recovery superauthority, not an ordinary hidden member.

Adding a principal or decrypting device and removing a principal or device
always creates a fresh VRK epoch and re-encrypts every current decryptable
artifact. Removed identities receive no later envelope. Role-only changes do
not normally rotate the VRK. Removing the last active owner is invalid. A
database-authority recovery transition must atomically appoint at least one
active replacement owner and rotate the VRK; recovery evidence never permits
an ownerless committed authorization state or a no-rekey owner recovery.

The exceptional database deny registry generation and digest are referenced by
each vault state, mutation link, protected anchor, and MongoDB compare-and-swap.
Adding an ordinary device does not require database-authority participation.
Placing a compromised device on the global deny fence across multiple vaults is
a bounded per-vault workflow, not one unbounded transaction: the signed
database-level generation rejects new signatures immediately, affected vaults
become `rekey-required` and reject writes, and each vault resumes only after its
VRK rotation commits. This does not retroactively remove old VRKs already held
by that device.

Approval policy is limited to `none` and `one-additional-owner`. The requesting
active owner device signs an immutable request digest covering the exact action
parameters, prior tuple and head, policy, nonce, and finite expiry. Lifecycle
state, appended approval evidence, and resolution time are excluded from that
immutable request core. An approval is from a distinct eligible owner, covers
that exact request digest and prior state, has a short expiry, and is consumed by
the protected transition. Policy changes use the prior policy. Ownership
transfer uses a separately domain-separated immutable intent digest covering
both parties and devices, target role and initiator disposition, database/vault,
the complete prior tuple and head, optional approval request, and finite
lifetime. It excludes only lifecycle state, signature timestamps and bytes,
recipient acceptance, publication time, and terminal time. The initiator signs
that digest and immutable core; the proposed owner separately signs the strict
acceptance record binding the same digest. Both signatures must verify against
active certified devices before the transition can consume the intent.

Pre-terminal approval requests and transfer intents are authenticated external
workflow artifacts, not members of the encrypted manifest whose head they bind.
Putting such an artifact into that prior manifest would create a digest fixed
point: the artifact binds the prior head while changing the encrypted-manifest
digest that produces that head. Candidate preparation instead verifies the exact
external quorum or accepted artifact against the authenticated prior state,
then atomically includes only its `consumed` or `published` terminal copy in the
next manifest. Unrelated retained workflow records remain byte-identical, and
the candidate recomputes a domain-separated digest over the exact non-secret
action projection before accepting approval evidence.

## Explicit nonclaims

- Revocation does not erase plaintext or earlier keys copied by a legitimate
  member.
- A reader can copy decrypted data outside the official client.
- MongoDB can delete, withhold, reorder, fork, and observe bounded metadata and
  timing.
- A device anchor detects rollback or a conflicting head only relative to state
  already observed by that device. It does not prevent a global split view.
- Ownership transfer does not transfer database recovery authority.
- A database authority can recover the VRK and plaintext as part of its explicit
  recovery power; it is not constrained by ordinary membership roles.
- Kavrix cannot protect keys or plaintext on a compromised unlocked host.

## Release gate

The public feature remains unavailable until identity/device lifecycle,
first-use receipts, recipient anchors, signed history/checkpoints, role
verification, rotation, atomic Mongo publication, operation recovery,
two-party transfer, approval replay protection, owner recovery, mixed-client
rejection, migration/resume, resource limits, plaintext canaries, and the full
concurrency/security matrix are all verified together.
