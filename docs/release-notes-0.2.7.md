# Kavrix 0.2.7 — Collaboration security foundations

Kavrix 0.2.7 hardens the internal foundations for a future collaborative-vault
protocol without exposing an unfinished collaboration command or public client
API. The existing zero-knowledge CLI behavior and published package boundary
remain unchanged.

## Authenticated migration and recovery state

Collaborative genesis now authenticates the protected legacy database revision
head, derives the vault root key from the database root key, and rechecks the
exact source head while holding the revision-anchor transition lock before it
prepares the collaborative row. This prevents a caller-supplied or stale source
state from becoming the authority for migration.

Owner recovery uses a separate database-root-key-protected authority rollback
anchor. Recovery opens, publications, and journal-only restarts accept only the
protected freshness base or an authenticated successor proof chain, then
advance the anchor under its exclusive transition lock. Recovery state cannot
silently fall back to the ordinary vault revision anchor.

## Canonical proof and journal binding

Operation and migration journals require the exact canonical proof entry in
prepared and terminal states. The journals bind mutation links, scope,
delegation, predecessor and resulting heads, witnesses, outcomes, and
request/source digests. Replays with the same operation identifier must carry
the same proof, and terminal failure is accepted only for an authenticated
committed incompatible outcome. Unauthenticated conflicts remain retryable.

Protected migration-anchor evidence is read and verified inside the journal's
exclusive transition callback, closing the cross-file read/replace race. Secure
file replacement also retries transient Windows `EPERM` rename failures while
revalidating the original file identity before every attempt.

Ownership-transfer validation covers all four specified outcomes for the
initiating owner: remain owner, become editor, become reader, or become removed.
The removed outcome requires the initiator's retained membership record to be
non-active; retained roles require an active membership with the exact role.

## Deliberate release boundary

These changes are protocol and security foundations, not a public collaboration
feature. No collaboration command is registered, `@kavrix/client` remains a
parked incubation package, and it is not included in the published npm package.
The supported `kavrix` CLI surface remains the one documented in the
implementation status and command reference.

## Release verification

Publication is gated by the complete local release suite, package smoke and
content inspection, database-container acceptance, dependency audit,
exact-commit CI and CodeQL, npm trusted publishing with provenance, registry
SHA-512 integrity reconciliation, and GitHub release creation only after npm
confirms `kavrix@0.2.7`.
