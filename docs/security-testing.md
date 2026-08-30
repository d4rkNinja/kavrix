# Security testing

Kavrix release validation always covers the packed local-file path and covers
direct MongoDB behavior when a disposable MongoDB prerequisite is available.

The active release workspace is `apps/cli`, `packages/core`, `packages/schemas`,
`packages/crypto`, `packages/key-files`, `packages/storage`, `packages/runner`,
and `packages/tui`. The other package directories remain
source-present but parked/incubating: they are not workspace members, are not
release artifacts, and are not counted by the coverage gate. Focused
collaboration tests under the parked `packages/client` source do run in root
Vitest as an incubation security gate, but do not make that package shipped. See
[Active release boundary](active-release-boundary.md) for the complete boundary
and command list.

## Required local checks

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:coverage
pnpm acceptance:pre-ci
pnpm acceptance:database-container
pnpm --filter kavrix package:smoke
pnpm --filter kavrix pack:check
pnpm audit --audit-level high
```

The schema and crypto suites cover malformed envelopes, tampering, associated
data swaps, key-slot wrapping, recovery-slot binding, and plaintext canaries.
Protected-file suites cover passphrase failures, database/vault binding,
tampering, path safety, and POSIX/Windows permission enforcement. The storage
suite covers fail-closed Mongo URI policy, exact idempotent Mongo index
definitions, two-collection transaction behavior,
and local schema, bounds, links, locks, compare-and-swap conflicts, atomic
publication, and deletion.

The root suite explicitly includes `packages/key-files/test/portable-key-files.test.ts`
and `packages/key-files/test/revision-anchor.test.ts`; the coverage gate scopes
source collection to the active release workspaces and enforces the configured
branch, function, line, and statement thresholds.

Every root Vitest worker runs against an isolated fake home directory created by
`scripts/test-isolated-home.mjs`, so suites cannot observe or mutate a real
machine-local datastore-profile registry under the user's home directory. Tests
that exercise profile selection target an explicit protected config directory.

`acceptance:database-container` packs the actual public package, installs it into
an isolated temporary prefix with a dedicated npm cache, and invokes only that
installed executable. Runtime-random passphrases, private labels, and plaintext
canaries travel through exact stdin frames, never argv or environment variables.
The test covers profile selection, two vaults, isolated writes/reads, a second
database and wrong-key rejection, switch-back integrity, legacy migration,
concurrent conflict, rollback-anchor rejection, catalog tampering, default label
redaction, package allowlisting, and scans of outputs and protected artifacts.

The runner handles `SIGINT` and `SIGTERM`, stops active children, attempts every
cleanup target even after an earlier cleanup failure, restores the caller's npm
cache setting, aggregates redacted operation/cleanup errors, and prints success
only after cleanup. Child probes cover signals both after handlers are installed
but before any potential root is created and while cleanup is in progress; the
parent owns every potential path and verifies its absence. Expected negative
tests run inside the same cleanup envelope.

## Execution-layer security suites

The credential execution features carry dedicated adversarial suites in the
root gate:

- `packages/runner`: environment-only injection with digest canaries and
  argv-secret refusal, cross-chunk output redaction, truncation-boundary
  redaction, timeout/abort termination, inherit/pipe passthrough modes, and
  reserved/colliding variable rejection.
- `packages/crypto` state envelope: round-trip, ciphertext/tag bit-flips,
  scope-kind/id/sequence transplant rejection, domain separation, and key/
  plaintext bounds.
- `packages/key-files` authorization-state file: canonical serialization
  strictness (reformatting fails closed), wrong-key integrity failure, foreign
  scope refusal, sequence advancement under the exclusive lock, missing-file
  semantics.
- `apps/cli` execution suites run the real CLI composition end to end:
  environment-only delivery with sha256 digests plus argv absence, parent
  environment purity, exit-code and signal-code propagation (`128+n`),
  captured-output redaction, project-file mappings and conflict rejection,
  deny/reveal/confirmation/hash-pin/TTL policy paths, grant expiry/exhaustion/
  revocation/name-vs-id resolution, policy-to-credential binding, read-only
  check/explain/lint/diff/suggest and grant-inspection state invariance, audit
  content without plaintext, sealed-state tamper and reformat failures, and a
  live agent-broker session covering
  allow with oversized-output framing, unknown permission, deny entry,
  confirmation-unavailable, unresolved executable, missing injection mapping,
  and exit-frame protocol termination.

Platform caveats: Windows command-script refusal is asserted through injected
platform parameters plus native `.cmd` cases on Windows runners; POSIX signal
exit-code mapping is exercised only where the platform delivers signals.

Packed database-container acceptance also invokes the installed archive's
policy check/explain/lint/diff/suggest and grant-show commands, verifies their
machine contracts, and compares the sealed authorization sidecar byte for byte
before and after every read-only group.

## MongoDB integration

The storage integration test runs only when `KAVRIX_MONGODB_URI` identifies a
disposable replica set or sharded topology with transaction support. It creates a
random test database, verifies transactional database/vault operations, the
automatic database `_id_` index, and the named unique
`{databaseId: 1, id: 1}` vault discovery index in the live service, then drops
only that generated database.

The collaboration integration suite uses the same gate and cleanup boundary. It
verifies exact collaboration index definitions, genesis activation, immutable
operation replay, late-conflict transaction rollback, permanent destruction
tombstones, ordinary-publication anti-resurrection, and absence of a generated
plaintext/key canary from raw MongoDB documents. Run it explicitly with:

```sh
vitest run --config packages/storage/vitest.config.ts \
  packages/storage/test/mongo-collaboration.integration.test.ts
```

The repository does not bootstrap MongoDB in CI: the workflow has no reviewed,
immutable, transaction-capable service image or safe replica-set startup path.
Unit doubles and a standalone server are not reported as live MongoDB proof.
Provide `KAVRIX_MONGODB_URI` in an authorized integration environment to obtain
that evidence.

## Environment caveats

No MongoDB daemon is bundled with the repository. Windows ACL checks and the
masked-terminal raw-mode restoration regression run on native Windows in the CI
matrix; macOS/Linux results are not substituted for Windows evidence. A passing
local suite is not evidence that a remote deployment is correctly configured for
TLS, transactions, authorization, or backup protection.
