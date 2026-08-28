# Implementation status

## Supported product

The supported product is the `kavrix` CLI in `apps/cli`. It persists one
authenticated encrypted database with multiple independently encrypted vaults
in a hardened local container or two MongoDB collections. Version 2 single-vault
documents remain supported through stable compatibility commands and explicit
copy-first migration. No Kavrix API server or sync daemon is required or
shipped; the legacy-compatible root `kavrix init` now generates a protected,
non-secret `~/.kavrix/config.toml` onboarding reference instead of the previous
guided wizard. Current commands do not load it automatically. The schema-driven
Ink showcase in `packages/tui`
remains available as the presentation boundary for interactive storage
selection, but the 0.2.3 no-argument TTY `init` path does not invoke it.

Active release workspaces:

- `@kavrix/schemas`: canonical database-container, vault, legacy, envelope, policy, and authorization-state schemas.
- `@kavrix/crypto`: DRK/VRK hierarchy, key derivation, wrapping, authenticated encryption, sealed state envelopes, and secure-byte helpers.
- `@kavrix/key-files`: protected database-owner key, recovery-kit, legacy key, revision-anchor, and sealed authorization-state files.
- `@kavrix/storage`: database-scoped local/MongoDB adapters and fail-closed URI/TLS policy.
- `@kavrix/runner`: shell-free child execution with minimal environments and secret redaction in captured output.
- `@kavrix/tui`: Ink components for the interactive storage-selection showcase (animated); presentational only, with static strings and no persistence or cryptography.
- `kavrix`: CLI composition, protected `config.toml` onboarding-reference generation, masked input, sanitized rendering, credential execution, policy firewall, and npm package.

The active-versus-parked source boundary and its verification commands are
recorded in [Active release boundary](active-release-boundary.md). The source
trees for the parked packages remain in the repository for incubation, but they
are not workspace members, release artifacts, or evidence for the active release.

## Implemented command surface

- legacy-compatible `init` that generates `~/.kavrix/config.toml`
  (`%USERPROFILE%\\.kavrix\\config.toml` on Windows) as a non-secret onboarding
  reference for the canonical profile/database/vault commands; it is not
  loaded automatically, lives in the secure `~/.kavrix` directory (mode
  `0o600` / user-only ACL), and is never overwritten once created;
- protected non-secret datastore profile add/list/use/status/remove;
- file/MongoDB database initialization, authenticated status, and MongoDB ping;
- encrypted database vault create/list/status/rename;
- database-owner key status, whole-local-database share-key creation, and database recovery create/verify/status/revoke/use;
- explicit legacy version 2 migration into an existing or explicitly initialized local database;
- encrypted put/get/list/view/search/stats operations;
- explicit override and reveal controls;
- has, rename, remove, vault list, and vault status;
- protected key-file status, verify, copy, replicate, assign, and rewrap;
- recovery-kit create, verify, status, revoke, and use;
- authenticated `doctor` validation and fail-closed `doctor health` repair;
- process-scoped credential execution (`kavrix run`) with environment-only
  injection, exit-code and signal preservation, optional project-file
  environment mappings, JSON capture with redaction, and no plaintext temp
  files (database-container profiles required);
- stored permission policies (`kavrix policy
create|list|show|remove|check|explain|lint|diff|suggest`) sealed
  in a DRK-derived, AEAD-authenticated sidecar bound to the database scope
  with a monotonic sequence; deny entries, command allowlists, SHA-256
  executable pins, execution-window TTLs, reveal gating, and confirmation
  requirements are evaluated fail-closed before any child spawns; read-only
  checks and explanations authenticate database metadata but never decrypt a
  vault payload, mutate authorization state, or create a missing sidecar;
- semantic policy linting for shadowed, impossible, overly broad, and expired
  authorization records; non-applying policy diffs; and review-only,
  monotonic-tightening suggestions derived solely from positive sanitized
  events in the bounded audit ring;
- temporary consumable grants (`kavrix grant <secret>|create|list|show|revoke`)
  with TTL, maximum uses, atomic use reservation under the protected-file
  lock, revocation, and distinct stable exit codes for expired, exhausted,
  revoked, and not-found references; inspection reports remaining uses,
  expiry, and effective restrictions without reading the credential;
- an append-bounded audit trail (`kavrix audit`) inside the same sealed state
  recording policy, grant, authorization, confirmation, and completion events
  with sanitized bounded metadata only;
- an AI-agent firewall (`kavrix agent run`, `kavrix agent exec`) that starts
  an agent with no credential material, brokers each requested operation over
  a local socket or named pipe behind a per-session token, evaluates the
  agent's configured permissions per request, and injects the secret directly
  into the authorized child only; requests have finite queue-wait and depth
  bounds, while frame size/rate, pending relay storage, and active child-stdin
  buffering are bounded and abusive connections are torn down;
- `kavrix frames [command]` stdin frame-contract reference and `kavrix status`
  routing summary.

Run `kavrix <command> --help` for exact options. Planned or retired commands must
not be documented as available.

## Recent hardening (post-0.2.0 external test report)

- `run --grant` resolves the grant's credential in-session before consuming any
  use; missing credentials fail with exit 11 without burning the use; grants
  without `env` inject under a derived destination name (`production/database`
  → `PRODUCTION_DATABASE`) and unmappable names fail closed with exit 14.
- Session error mapping no longer reports duplicate labels, missing
  credentials, invalid input, or secret-frame mistakes as "Database
  authentication failed"; reviewed command-layer errors pass through and store
  codes map to truthful classes with documented exit codes (10/11/14/15/16).
- Usage errors exit `2`; wrong passphrases exit `10`; missing credentials exit
  `11` per the CLI reference table.
- Local file locks record their owner PID; locks from provably dead processes
  are auto-removed on the next invocation while live owners keep failing
  closed with a visible message. `db doctor health [--accept-current]` adds a
  bounded container repair: full authenticated verification, then re-anchor of
  the local rollback guard after explicit human consent.
- Reserved vault identifiers (`__proto__`, `constructor`, `prototype`) are
  refused at init with reviewed messages.
- Multi-line and empty credential values are supported via
  `put --value-stdin-base64` (one strict base64 frame).
- The documented project-file example now validates; agent permissions require
  `env` for exec injection as documented; search accepts glob patterns plus
  `--case-sensitive`; credential names reject whitespace/slash/dot abuse;
  owner-visible vault labels are available via `--show-labels`; share-key
  staleness is warned at creation; `init` defaults to the local file datastore
  outside the guided wizard.

## Security properties

- plaintext labels, values, DRKs, VRKs, and unlock keys do not cross the storage boundary;
- database/catalog/wrapped-key AAD binds database and vault identity, purpose,
  versions, revision, and authenticated metadata digests;
- a DRK-authenticated local anchor rejects rollback, same-revision forks, and
  inconsistent catalog/vault heads before plaintext is returned;
- fresh local-share keys carry a protected one-use exact-snapshot bootstrap;
  owner anchors remain mandatory and recovery anchors advance only inside the
  authenticated recovery workflow;
- local publication is atomic and MongoDB multi-document publication requires transactions;
- remote MongoDB requires explicit validated TLS and insecure TLS flags are rejected;
- protected files use bounded formats, atomic creation, and permission checks;
- terminal output is sanitized and values are masked unless reveal is explicit;
- the authorization sidecar is sealed with XChaCha20-Poly1305 under a key
  derived (HKDF-SHA-256) from the database root key and bound to the exact
  scope identity and sequence; any tampering or reformatting fails closed;
- `kavrix run` never places secrets in argv (enforced by the runner), spawns
  through `shell: false` argument arrays, wipes injected environment buffers
  after child exit (best effort in JavaScript), and propagates child exit
  codes and signal-death codes (128+n);
- agent broker requests are token-checked, serialized per session, evaluated
  against configured permissions before spawn, and terminated by an explicit
  exit frame so denials are distinguishable from broken connections.

## Verification boundary

The active release gate covers the seven workspaces listed above: `apps/cli`,
`packages/schemas`, `packages/crypto`, `packages/key-files`, `packages/storage`,
`packages/runner`, and `packages/tui`. Root Vitest includes the active CLI,
schema, crypto, key-file, storage, runner, and TUI suites, including the
portable-key and revision-anchor security tests; its coverage scope is
restricted to those same seven source trees. Each Vitest worker runs against an
isolated fake home directory so machine-local Kavrix state, such as a real
datastore-profile registry, cannot influence results. Parked package sources
are not counted as active release coverage and are not represented as shipped
features in this ledger.

The current verification commands and their platform limits are maintained in
[`docs/security-testing.md`](security-testing.md). A feature is not marked
verified here merely because source or tests exist in a parked package.

## Release gates

A release requires formatting, lint, strict typecheck, unit tests, build,
packed-install smoke, packed database-container acceptance on Windows/macOS/Linux,
package allowlist inspection, SBOM verification, dependency audit, exact-SHA CI
and CodeQL, and npm OIDC provenance. The repository's live MongoDB integration
test runs only when `KAVRIX_MONGODB_URI` points to a disposable transaction-capable
replica set. CI does not download or claim an unpinned MongoDB service. Windows
ACL evidence depends on the actual runner account and filesystem.

The verification result for a release belongs in its CI logs and GitHub release,
not as a permanently stale test count in this document.

## Known limits

MongoDB can observe opaque database/vault IDs, revisions, timestamps, ciphertext
sizes, and access patterns. A database operator can delete or withhold data. The
local revision anchor is fail-closed but is not remote tamper-proof storage. A
fresh local-share key trusts only the exact authenticated snapshot captured when
the key was created; after first use its companion anchor is mandatory.

Execution-layer limits that are verified or documented rather than claimed away:

- process-scoped injection cannot stop the authorized program (or anything
  running as the same user) from reading its own environment and disclosing it;
  inherited stdio in default `run` mode is unfiltered by design;
- executable hash pinning narrows but cannot close the resolve-to-spawn window;
  JavaScript cannot open-then-execute one file descriptor portably;
- Windows command scripts (.bat/.cmd/.com) are refused outright because
  launching them requires shell argument re-parsing; invoke real executables;
- policy/grant state integrity is authenticated against forgery and corruption,
  but a same-user attacker who can rewrite the datastore can also restore older
  authentic sidecar bytes; sequence numbers make regressions visible to audit
  review, not cryptographically impossible;
- read-only policy/grant/audit inspection verifies the key binding, database
  metadata, exact revision anchor, and sealed authorization state, but
  deliberately does not decrypt or verify catalog/vault ciphertext; any later
  credential-reading operation performs the full authenticated open;
- agent descendants inherit the broker endpoint and session token; policy still
  gates every individual request, and secrets live in broker memory for the
  session lifetime subject to the same unlocked-host inspection limits.

User identities, public enrollment, recipient discovery, vault grants, reader/
editor/owner roles, revocation with VRK rotation, and ownership transfer are not
implemented. Environments beyond project-file secret mappings, groups/services,
structured items, and typed fields are also deferred. Legacy version 2 vaults
support `get --reveal` semantics unchanged; policies, grants, audit, run, and
agent commands require a database-container profile. Local-file mode has no
fine-grained sharing: sharing its data file and a freshly generated matching
share key grants full database access once unlocked.

Kavrix does not protect an unlocked host from administrators, same-user malware,
keyloggers, screen/terminal/clipboard capture, process-memory inspection, swap,
crash dumps, or terminal capture of child output. JavaScript cannot guarantee
complete zeroization. Losing all valid key files and recovery kits is
unrecoverable by design.
